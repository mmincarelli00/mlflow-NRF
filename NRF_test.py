#!/usr/bin/env python3
"""Score the frozen best model of every family on the untouched test period and compare them.

Reads artifacts/best_models.json written by train.py (best hyper-parameters, validation-frozen alert
threshold, model file), rebuilds the features from the raw tables, scores the test split and logs one
MLflow parent run ("test_comparison") with one nested run per family. It also writes:

  results/test_comparison.csv       one row per family (window-level and episode-level metrics)
  results/test_comparison.md        the same table, ready to paste
  results/test_subtype_recall.csv   episode recall per anomaly subtype
  results/test_benign_fp.csv        share of windows alerted per benign-change subtype (hard negatives)
  results/pr_curves.png, subtype_recall.png, benign_fp.png

Usage:  python test.py --data-dir data --artifacts-dir artifacts --out-dir results
"""
from __future__ import annotations

import argparse
import json
import os
import warnings
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import mlflow  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import precision_recall_curve  # noqa: E402

from NRF_train import _finite, benign_breakdown, evaluate, prepare  # noqa: E402  (importing train also resolves pickled classes)

HEADLINE = ["pr_auc", "roc_auc", "recall_at_fpr", "precision", "f1", "fpr", "alerts_per_day", "fp_per_day_benign",
            "benign_fpr", "episode_recall", "mttd_h"]


def heatmap(ax, mat: pd.DataFrame, title: str, fmt="{:.2f}"):
    im = ax.imshow(mat.to_numpy(dtype=float), vmin=0, vmax=1, cmap="viridis", aspect="auto")
    ax.set_xticks(range(mat.shape[1]), mat.columns, rotation=40, ha="right")
    ax.set_yticks(range(mat.shape[0]), mat.index)
    ax.set_title(title)
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            v = mat.iat[i, j]
            if np.isfinite(v):
                ax.text(j, i, fmt.format(v), ha="center", va="center", color="white" if v < 0.6 else "black", fontsize=8)
    return im


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default=None, help="defaults to the directory recorded by train.py")
    ap.add_argument("--artifacts-dir", default="artifacts")
    ap.add_argument("--out-dir", default="results")
    ap.add_argument("--tracking-uri", default=None)
    ap.add_argument("--experiment", default=None)
    a = ap.parse_args()

    reg = json.loads((Path(a.artifacts_dir) / "best_models.json").read_text())
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    feats, X, masks, meta, digest = prepare(a.data_dir or reg["data_dir"])
    if digest != reg["data_digest"]:
        warnings.warn(f"data digest {digest} differs from the one used for training ({reg['data_digest']}): "
                      "regenerate the data and re-run train.py before trusting these numbers")
    te = masks["test"]
    df_te, X_te = feats[te].reset_index(drop=True), X[te]
    print(f"test period: {df_te.window_start.min()} -> {df_te.window_start.max()} | rows {len(df_te)} | "
          f"anomalous windows {df_te.label.sum()} | episodes {df_te[df_te.label == 1].episode_id.nunique()}")

    mlflow.set_tracking_uri(a.tracking_uri or os.environ.get("MLFLOW_TRACKING_URI") or reg["tracking_uri"])
    mlflow.set_experiment(a.experiment or reg["experiment"])

    rows, sub_rows, benign_rows, curves = [], {}, {}, {}
    common = {"stage": "test", "data_snapshot_id": digest, "split": "time_based", "label_source": "injected",
              "threshold_source": f"validation quantile, target_fpr={reg['target_fpr']}"}
    with mlflow.start_run(run_name="test_comparison") as parent:
        mlflow.set_tags({**common, "run_level": "comparison"})
        for family, info in reg["families"].items():
            model = joblib.load(info["model_path"])
            scores = model.score(X_te)
            thr = info["threshold"]
            m = evaluate(df_te, scores, thr)
            bb = benign_breakdown(df_te, scores, thr)
            p, r, _ = precision_recall_curve(df_te.label, scores)
            curves[family] = (r, p, m["pr_auc"])
            val = info["val_metrics"]
            with mlflow.start_run(run_name=f"test-{family}", nested=True):
                mlflow.set_tags({**common, "model_family": family, "run_level": "test_model",
                                 "trained_in_run": info["trial_run_id"], "is_baseline": str(family == "robust_z").lower()})
                mlflow.log_params({**{f"param_{k}": v for k, v in info["params"].items()}, "frozen_threshold": thr})
                mlflow.log_metrics(_finite({**{f"test_{k}": v for k, v in m.items()},
                                            "gap_pr_auc_test_minus_val": m["pr_auc"] - val["pr_auc"],
                                            **{f"test_benign_fp_{k}": v for k, v in bb.items()}}))
            rows.append(dict(family=family, params=json.dumps(info["params"]), **{k: m.get(k, np.nan) for k in HEADLINE},
                             val_pr_auc=val["pr_auc"], gap_pr_auc=m["pr_auc"] - val["pr_auc"]))
            sub_rows[family] = {k.replace("ep_recall_", ""): v for k, v in m.items() if k.startswith("ep_recall_")}
            benign_rows[family] = bb

        res = pd.DataFrame(rows).sort_values("pr_auc", ascending=False).reset_index(drop=True)
        sub = pd.DataFrame(sub_rows).T.reindex(res.family)
        ben = pd.DataFrame(benign_rows).T.reindex(res.family)
        res.to_csv(out / "test_comparison.csv", index=False)
        sub.to_csv(out / "test_subtype_recall.csv")
        ben.to_csv(out / "test_benign_fp.csv")
        show = res[["family"] + HEADLINE + ["gap_pr_auc"]].round(3)
        (out / "test_comparison.md").write_text(show.to_markdown(index=False) if _has_tabulate() else show.to_string(index=False))

        fig, ax = plt.subplots(figsize=(6.5, 5))
        for fam, (r, p, ap_) in sorted(curves.items(), key=lambda kv: -kv[1][2]):
            ax.plot(r, p, label=f"{fam} (AP={ap_:.2f})", lw=2 if fam == "robust_z" else 1.4, ls="--" if fam == "robust_z" else "-")
        ax.set(xlabel="recall (windows)", ylabel="precision", title="Test PR curves", xlim=(0, 1), ylim=(0, 1.02))
        ax.legend(fontsize=8)
        ax.grid(alpha=0.3)
        fig.tight_layout()
        fig.savefig(out / "pr_curves.png", dpi=140)
        plt.close(fig)
        fig, ax = plt.subplots(figsize=(7.5, 3.8))
        im = heatmap(ax, sub, "Episode recall per anomaly subtype (test)")
        fig.colorbar(im, ax=ax)
        fig.tight_layout()
        fig.savefig(out / "subtype_recall.png", dpi=140)
        plt.close(fig)
        fig, ax = plt.subplots(figsize=(9, 3.8))
        im = heatmap(ax, ben, "Share of benign-change windows alerted (lower is better)")
        fig.colorbar(im, ax=ax)
        fig.tight_layout()
        fig.savefig(out / "benign_fp.png", dpi=140)
        plt.close(fig)
        for f in ("test_comparison.csv", "test_comparison.md", "test_subtype_recall.csv", "test_benign_fp.csv",
                  "pr_curves.png", "subtype_recall.png", "benign_fp.png"):
            mlflow.log_artifact(str(out / f), artifact_path="test_report")
        best = res.iloc[0]
        mlflow.log_metrics(_finite({"best_test_pr_auc": best.pr_auc}))
        mlflow.set_tag("best_family_on_test", best.family)

    pd.set_option("display.width", 220)
    print("\nTest results (thresholds frozen on validation):")
    print(show.to_string(index=False))
    print("\nEpisode recall per subtype:")
    print(sub.round(2).to_string())
    print("\nShare of benign-change windows alerted:")
    print(ben.round(2).to_string())
    print(f"\nreport written to {out}/")


def _has_tabulate() -> bool:
    try:
        import tabulate  # noqa: F401
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    main()
