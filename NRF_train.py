#!/usr/bin/env python3
"""Train and compare model families for rogue / changed NF registration and new call-edge detection.

Model families (one MLflow parent run each, one nested child run per hyper-parameter trial):
  robust_z               BASELINE  median/MAD z-score per feature, one-sided, summed or max-ed
  isolation_forest       unsupervised, fitted on clean windows only
  lof                    Local Outlier Factor (novelty mode), fitted on clean windows only
  hist_gbm               supervised HistGradientBoosting (needs labels: injected / analyst feedback)
  rules_only             hand-written weighted identity/policy rules, no learning ("must-beat" arm)
  hybrid_rules_iforest   rules + Isolation Forest rank (hard checks plus ML ranking)

Protocol
  * time-based split (see features.split_masks): train (incl. clean baseline) -> val -> test
  * unsupervised models are fitted on train windows with label == 0 (benign changes included)
  * the best trial per family is picked on validation PR-AUC (ties: episode recall)
  * the alert threshold is the (1 - target_fpr) quantile of validation negatives and is then frozen
  * test.py scores the frozen models on the untouched test period

Usage:  python train.py --data-dir data --artifacts-dir artifacts
View:   mlflow ui --backend-store-uri sqlite:///mlflow.db
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import time
from pathlib import Path

import joblib
import mlflow
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor

from features import RISK_COLS, build_features, load_raw, risk_matrix, split_masks

EXPERIMENT = "nrf/rogue_registration_and_call_edges"
FEATURE_SET_VERSION = "v1-14items-16cols"


# =============================================================================== models
class RobustZ:
    """Baseline. z = (x - median) / max(1.4826 * MAD, eps), one-sided (only 'riskier than usual' counts).

    Binary flags have MAD = 0, so `eps` acts as the scale floor: a single raised flag gives z = 1 / eps.
    """
    name, supervised = "robust_z", False

    def __init__(self, eps=0.25, zmax=8.0, agg="sum"):
        self.eps, self.zmax, self.agg = eps, zmax, agg

    def fit(self, X, y=None):
        self.med_ = np.median(X, axis=0)
        mad = 1.4826 * np.median(np.abs(X - self.med_), axis=0)
        self.scale_ = np.maximum(mad, self.eps)
        return self

    def score(self, X):
        z = np.clip((X - self.med_) / self.scale_, 0.0, self.zmax)
        return z.sum(axis=1) if self.agg == "sum" else z.max(axis=1)


class IForest:
    name, supervised = "isolation_forest", False

    def __init__(self, n_estimators=300, max_samples=256, max_features=1.0, seed=0):
        self.n_estimators, self.max_samples, self.max_features, self.seed = n_estimators, max_samples, max_features, seed

    def fit(self, X, y=None):
        self.m_ = IsolationForest(n_estimators=self.n_estimators, max_samples=min(self.max_samples, len(X)),
                                  max_features=self.max_features, random_state=self.seed, n_jobs=-1).fit(X)
        return self

    def score(self, X):
        return -self.m_.score_samples(X)


class LOF:
    name, supervised = "lof", False

    def __init__(self, n_neighbors=30, max_fit_rows=12000, seed=0):
        self.n_neighbors, self.max_fit_rows, self.seed = n_neighbors, max_fit_rows, seed

    def fit(self, X, y=None):
        if len(X) > self.max_fit_rows:
            X = X[np.random.default_rng(self.seed).choice(len(X), self.max_fit_rows, replace=False)]
        self.m_ = LocalOutlierFactor(n_neighbors=self.n_neighbors, novelty=True, n_jobs=-1).fit(X)
        return self

    def score(self, X):
        return np.nan_to_num(-self.m_.score_samples(X), nan=0.0, posinf=1e6, neginf=0.0)


class HistGBM:
    name, supervised = "hist_gbm", True

    def __init__(self, learning_rate=0.1, max_leaf_nodes=31, max_iter=200, seed=0):
        self.learning_rate, self.max_leaf_nodes, self.max_iter, self.seed = learning_rate, max_leaf_nodes, max_iter, seed

    def fit(self, X, y=None):
        self.m_ = HistGradientBoostingClassifier(learning_rate=self.learning_rate, max_leaf_nodes=self.max_leaf_nodes,
                                                 max_iter=self.max_iter, class_weight="balanced",
                                                 random_state=self.seed).fit(X, y)
        return self

    def score(self, X):
        return self.m_.predict_proba(X)[:, 1]


_STRICT = {"r_id_unknown": 6, "r_addr_unknown": 4, "r_cert_mismatch": 3, "r_second_source": 2, "r_orch_unmatched": 1,
           "r_outside_window": 0.5, "r_diff_risk": 0.5, "r_allowlist_widened": 2, "r_ranges_added": 1,
           "r_token_sub_mismatch": 4, "r_fast_traffic": 0, "r_traffic_share": 2, "r_new_edges": 1,
           "r_policy_violation": 6, "r_scope_mismatch": 3, "r_denied_on_new": 2}
_BALANCED = {k: (3 if k in ("r_id_unknown", "r_addr_unknown", "r_cert_mismatch", "r_token_sub_mismatch",
                            "r_policy_violation", "r_scope_mismatch") else 1) for k in RISK_COLS}
RULE_PROFILES = {"strict": _STRICT, "balanced": _BALANCED}


class RulesOnly:
    """Weighted identity / policy rules (domain knowledge, nothing is learned)."""
    name, supervised = "rules_only", False

    def __init__(self, profile="strict"):
        self.profile = profile
        self.w_ = np.array([RULE_PROFILES[profile][c] for c in RISK_COLS], dtype=float)

    def fit(self, X, y=None):
        return self

    def score(self, X):
        return X @ self.w_


class HybridRulesIForest:
    """Hard rules decide the bulk of the score; Isolation Forest (rank in 0..1) orders what the rules do not cover."""
    name, supervised = "hybrid_rules_iforest", False

    def __init__(self, alpha=3.0, n_estimators=300, profile="strict", seed=0):
        self.alpha, self.n_estimators, self.profile, self.seed = alpha, n_estimators, profile, seed
        self.rules_ = RulesOnly(profile)

    def fit(self, X, y=None):
        self.if_ = IForest(self.n_estimators, 256, 1.0, self.seed).fit(X)
        self.ref_ = np.sort(self.if_.score(X))
        return self

    def score(self, X):
        pct = np.searchsorted(self.ref_, self.if_.score(X)) / len(self.ref_)
        return self.rules_.score(X) + self.alpha * pct


FAMILIES = {
    "robust_z": (RobustZ, {"eps": [0.1, 0.25, 0.5], "zmax": [4.0, 8.0], "agg": ["sum", "max"]}),
    "isolation_forest": (IForest, {"n_estimators": [200, 500], "max_samples": [256, 1024], "max_features": [0.6, 1.0]}),
    "lof": (LOF, {"n_neighbors": [10, 30, 60]}),
    "hist_gbm": (HistGBM, {"learning_rate": [0.05, 0.1], "max_leaf_nodes": [15, 31]}),
    "rules_only": (RulesOnly, {"profile": ["strict", "balanced"]}),
    "hybrid_rules_iforest": (HybridRulesIForest, {"alpha": [2.0, 5.0], "n_estimators": [300]}),
}


def trials(grid: dict):
    keys = list(grid)
    for vals in itertools.product(*grid.values()):
        yield dict(zip(keys, vals))


# =============================================================================== evaluation
def choose_threshold(neg_scores: np.ndarray, target_fpr: float) -> float:
    return float(np.quantile(neg_scores, 1.0 - target_fpr))


def evaluate(df: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    """Window-level and episode-level metrics for one split. `df` needs label/subtype/episode_id/window_start."""
    y = df.label.to_numpy()
    alerts = scores > threshold
    days = max(df.window_start.nunique() / 24.0, 1e-9)
    tp, fp = int((alerts & (y == 1)).sum()), int((alerts & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    benign = df.subtype.str.startswith("benign").to_numpy()
    out = {
        "pr_auc": float(average_precision_score(y, scores)) if pos else float("nan"),
        "roc_auc": float(roc_auc_score(y, scores)) if pos and neg else float("nan"),
        "recall_at_fpr": tp / max(pos, 1), "precision": tp / max(tp + fp, 1), "fpr": fp / max(neg, 1),
        "alerts_per_day": float(alerts.sum()) / days,
        "fp_per_day_benign": float((alerts & benign).sum()) / days,
        "benign_fpr": float((alerts & benign).sum()) / max(int(benign.sum()), 1),
    }
    out["f1"] = 2 * out["precision"] * out["recall_at_fpr"] / max(out["precision"] + out["recall_at_fpr"], 1e-12)
    t = pd.DataFrame({"ep": df.episode_id.to_numpy(), "sub": df.subtype.to_numpy(), "alert": alerts,
                      "win": df.window_start.to_numpy(), "y": y})
    t = t[t.y == 1]
    if len(t):
        eps = t.groupby("ep").agg(sub=("sub", "first"), det=("alert", "any"), start=("win", "min"))
        first_alert = t[t.alert].groupby("ep").win.min()
        eps["delay_h"] = (first_alert - eps.start).dt.total_seconds() / 3600.0
        out["episode_recall"] = float(eps.det.mean())
        out["mttd_h"] = float(eps.delay_h.mean()) if eps.delay_h.notna().any() else float("nan")
        for sub, g in eps.groupby("sub"):
            out[f"ep_recall_{sub}"] = float(g.det.mean())
    return out


def benign_breakdown(df: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    """Share of windows alerted for every benign-change subtype (hard negatives)."""
    alerts = scores > threshold
    res = {}
    for sub in sorted(s for s in df.subtype.unique() if s.startswith("benign")):
        m = (df.subtype == sub).to_numpy()
        res[sub] = float(alerts[m].mean())
    return res


def _finite(d: dict) -> dict:
    return {k: float(v) for k, v in d.items() if v is not None and np.isfinite(v)}


def prepare(data_dir: str):
    """Load raw tables, build features and the time-based splits."""
    raw, meta = load_raw(data_dir)
    feats = build_features(raw, meta)
    masks = split_masks(feats, meta)
    X = risk_matrix(feats).to_numpy()
    digest = hashlib.md5(pd.util.hash_pandas_object(feats[["nf_instance_id", "window_start"]], index=False)
                         .to_numpy().tobytes() + X.tobytes()).hexdigest()[:12]
    return feats, X, masks, meta, digest


# =============================================================================== main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--artifacts-dir", default="artifacts")
    ap.add_argument("--tracking-uri", default=os.environ.get("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    ap.add_argument("--experiment", default=EXPERIMENT)
    ap.add_argument("--target-fpr", type=float, default=0.005, help="window-level FPR used to freeze the threshold")
    ap.add_argument("--families", nargs="*", default=list(FAMILIES))
    a = ap.parse_args()

    art = Path(a.artifacts_dir)
    (art / "models").mkdir(parents=True, exist_ok=True)
    feats, X, masks, meta, digest = prepare(a.data_dir)
    tr, va = masks["train"], masks["val"]
    y_tr = feats.label.to_numpy()[tr]
    X_tr, X_va, df_va = X[tr], X[va], feats[va]
    X_clean = X_tr[y_tr == 0]
    print(f"data digest {digest} | train {tr.sum()} (clean {len(X_clean)}, pos {y_tr.sum()}) | "
          f"val {va.sum()} (pos {df_va.label.sum()}) | split {masks['bounds']}")

    mlflow.set_tracking_uri(a.tracking_uri)
    mlflow.set_experiment(a.experiment)
    registry, summary = {}, []
    common_tags = {"stage": "train", "anomaly_class": "rogue_registration+call_edges", "feature_set_version": FEATURE_SET_VERSION,
                   "window_size": "1h", "data_snapshot_id": digest, "label_source": "injected",
                   "split": "time_based", "train_end": masks["bounds"]["train_end"], "val_end": masks["bounds"]["val_end"]}
    data_params = {"n_features": len(RISK_COLS), "target_fpr": a.target_fpr, "train_rows": int(tr.sum()),
                   "train_clean_rows": int(len(X_clean)), "val_rows": int(va.sum()), "val_positives": int(df_va.label.sum())}

    for family in a.families:
        cls, grid = FAMILIES[family]
        best = None
        with mlflow.start_run(run_name=family) as parent:
            mlflow.set_tags({**common_tags, "model_family": family, "is_baseline": str(family == "robust_z").lower(),
                             "supervised": str(cls.supervised).lower(), "run_level": "family"})
            mlflow.log_params({**data_params, "n_trials": len(list(trials(grid)))})
            for i, params in enumerate(trials(grid)):
                with mlflow.start_run(run_name=f"{family}-{i:02d}", nested=True) as child:
                    mlflow.set_tags({**common_tags, "model_family": family, "run_level": "trial"})
                    mlflow.log_params(params)
                    model = cls(**params)
                    t0 = time.perf_counter()
                    model.fit(X_tr, y_tr) if cls.supervised else model.fit(X_clean)
                    fit_s = time.perf_counter() - t0
                    t0 = time.perf_counter()
                    s_va = model.score(X_va)
                    infer_ms = (time.perf_counter() - t0) * 1000.0 / max(len(X_va), 1) * 1000.0
                    thr = choose_threshold(s_va[df_va.label.to_numpy() == 0], a.target_fpr)
                    m = evaluate(df_va, s_va, thr)
                    mlflow.log_metrics(_finite({**{f"val_{k}": v for k, v in m.items()}, "val_threshold": thr,
                                                "fit_seconds": fit_s, "infer_ms_per_1k": infer_ms}))
                    key = (m["pr_auc"], m.get("episode_recall", 0.0))
                    if best is None or key > best["key"]:
                        best = dict(key=key, params=params, model=model, thr=thr, metrics=m,
                                    run_id=child.info.run_id, infer_ms=infer_ms)
                    print(f"  {family:22s} {params} val_pr_auc={m['pr_auc']:.3f} "
                          f"recall@fpr={m['recall_at_fpr']:.3f} ep_recall={m.get('episode_recall', float('nan')):.3f}")
            path = art / "models" / f"{family}.joblib"
            joblib.dump(best["model"], path)
            mlflow.log_params({f"best_{k}": v for k, v in best["params"].items()})
            mlflow.log_metrics(_finite({f"best_val_{k}": v for k, v in best["metrics"].items()}))
            mlflow.set_tag("best_trial_run_id", best["run_id"])
            mlflow.log_artifact(str(path), artifact_path="best_model")
            registry[family] = dict(parent_run_id=parent.info.run_id, trial_run_id=best["run_id"], params=best["params"],
                                    threshold=best["thr"], model_path=str(path), supervised=cls.supervised,
                                    val_metrics=best["metrics"])
            summary.append(dict(family=family, **best["params"], **{f"val_{k}": v for k, v in best["metrics"].items()
                                                                     if not k.startswith("ep_recall_")}))

    sdf = pd.DataFrame(summary)
    sdf.to_csv(art / "validation_summary.csv", index=False)
    (art / "best_models.json").write_text(json.dumps(dict(
        data_dir=a.data_dir, data_digest=digest, experiment=a.experiment, tracking_uri=a.tracking_uri,
        target_fpr=a.target_fpr, split=masks["bounds"], families=registry), indent=2, default=str))
    show = ["family", "val_pr_auc", "val_recall_at_fpr", "val_episode_recall", "val_alerts_per_day", "val_fp_per_day_benign"]
    print("\nBest trial per family (validation):")
    print(sdf[show].sort_values("val_pr_auc", ascending=False).round(3).to_string(index=False))
    print(f"\nregistry written to {art / 'best_models.json'} -> run `python test.py`")


if __name__ == "__main__":
    # re-import under the module name so pickled model classes resolve as `train.<Class>` in test.py
    from train import main as _main

    _main()
