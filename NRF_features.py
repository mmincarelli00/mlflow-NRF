#!/usr/bin/env python3
"""Feature engineering for rogue / changed NF registrations and new NF-to-NF call edges.

It turns the raw tables into the table the models learn from: one row per NF instance per hour, with the 14 selected features (16 columns) and the ground truth. 
It writes nothing by default. It is mainly a library that train.py and test.py import

The 14 selected features (items) -> 16 columns (items 5 and 10 each yield two columns):

 #   column                          source event(s)
 1   id_in_inventory                 E1/E2 nfInstanceId           + CMDB inventory
 2   addr_in_inventory               E1/E2 fqdn, ipv4Addresses    + CMDB inventory (state, carried forward)
 3   cert_matches_profile            E8 TLS client cert SAN       + E1/E2 profile fqdn (state, carried forward)
 4   second_source_for_id            E1/E2 + E8 (cert fp / source IP differ from previous event of same id)
 5   orch_event_matched              E1/E2                        + orchestrator events (+/-10 min)
 5   in_change_window                E1/E2                        + maintenance calendar
 6   diff_risk_score                 E2 JSON-patch paths (or E1 vs previous profile), risk-weighted
 7   allowlist_widened               E1/E2 allowedNfTypes / allowedNssais / allowedOperationsPerNfType additions
 8   ranges_added                    E1/E2 supiRanges, gpsiRanges, TAIs, DNNs, S-NSSAIs additions
 9   token_sub_matches_cert          E7 access-token `sub` vs E8 TLS identity
10   time_to_first_traffic_s         E1 -> first E9 request received by the instance
10   new_instance_traffic_share_10m  E6/E9 share of the NF type's traffic served within 10 min of E1
11   edge_is_new                     E9 distinct first-seen edges (consumer type, service, operation)
12   edge_policy_violation           E9 edges answered 2xx although consumer type is not allowed for the service
13   token_scope_vs_call_mismatch    E9 share of calls whose token scope/aud differs from the called service
14   edge_403_ratio                  E9 share of denied (401/403) calls on first-seen edges

Neutral values: windows without a registration/update event get "no unmatched change" values
(orch_event_matched = in_change_window = 1, scores = 0, time_to_first_traffic_s = 3600).

`risk_matrix()` converts the raw columns into "higher = riskier" model inputs (flags inverted,
counts log-scaled, time-to-first-traffic mapped to 1/(1+t/60)).


Event tags E1-E9
----------------
E1-E9 are this project's own shorthand, not 3GPP names. Each maps to a 3GPP operation, except E8,
which is the TLS layer underneath every SBI connection. 
They represent the SBI protocol events that can be used in real networks to build the features.
 
E1  NF registration
      3GPP service:  Nnrf_NFManagement, NFRegister
      HTTP request:  PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}  (full NF profile)
      From -> to:    NF -> NRF
      Spec:          TS 29.510
      Observed at:   NRF access or audit log
      Simulation:    nrf_events.csv, event_type = REGISTER
      Features:      1-8, 10
 
E2  NF profile update (heartbeats are also updates)
      3GPP service:  Nnrf_NFManagement, NFUpdate
      HTTP request:  PATCH (JSON Patch) or PUT on /nnrf-nfm/v1/nf-instances/{nfInstanceId}
      From -> to:    NF -> NRF
      Spec:          TS 29.510
      Observed at:   NRF access or audit log
      Simulation:    nrf_events.csv, event_type = UPDATE (heartbeats not included)
      Features:      2-8
 
E3  NF deregistration
      3GPP service:  Nnrf_NFManagement, NFDeregister
      HTTP request:  DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}
      From -> to:    NF -> NRF
      Spec:          TS 29.510
      Observed at:   NRF access log
      Simulation:    not generated
      Features:      none
 
E4  Status subscription
      3GPP service:  Nnrf_NFManagement, NFStatusSubscribe
      HTTP request:  POST /nnrf-nfm/v1/subscriptions
      From -> to:    NF -> NRF
      Spec:          TS 29.510
      Observed at:   NRF access log
      Simulation:    not generated
      Features:      none
 
E5  Status notification
      3GPP service:  Nnrf_NFManagement, NFStatusNotify
      HTTP request:  POST to the subscriber's nfStatusNotificationUri callback
      From -> to:    NRF -> subscribed NF
      Spec:          TS 29.510
      Observed at:   NRF outbound log
      Simulation:    not generated
      Features:      none
 
E6  NF discovery
      3GPP service:  Nnrf_NFDiscovery
      HTTP request:  GET /nnrf-disc/v1/nf-instances?target-nf-type=...&requester-nf-type=...
      From -> to:    NF or SCP -> NRF
      Spec:          TS 29.510
      Observed at:   NRF access log
      Simulation:    not generated
      Features:      none (it only explains why a rogue NF gains traffic, feature 10b)
 
E7  Access token request
      3GPP service:  Nnrf_AccessToken (OAuth 2.0 client credentials)
      HTTP request:  POST /oauth2/token
      From -> to:    NF -> NRF
      Spec:          TS 29.510, TS 33.501
      Observed at:   NRF token-endpoint log
      Simulation:    token_requests.csv
      Features:      9
 
E8  TLS identity
      3GPP service:  mutual TLS handshake under every SBI connection (not a 3GPP message)
      HTTP request:  none (client certificate SAN, certificate fingerprint, source IP)
      From -> to:    both sides of any connection
      Spec:          TS 33.501
      Observed at:   wherever TLS terminates: NRF, SCP or mesh sidecar
      Simulation:    columns src_ip, cert_san, cert_fp in nrf_events.csv
      Features:      3, 4, 9
 
E9  SBI service call
      3GPP service:  any NF-to-NF service, such as Nudm_SDM, Nausf_UEAuthentication, Nudr_DR
      HTTP request:  any method and path, with "Authorization: Bearer <token>"
      From -> to:    consumer -> producer, directly or via the SCP
      Spec:          TS 29.500, TS 23.501 Annex E, and each service's own spec
      Observed at:   SCP or mesh access logs, producer metrics
      Simulation:    sbi_calls.csv, producer_load.csv, post_register_traffic.csv
      Features:      10-14
 
Notes:
  * E1, E2, E3 and E7 are calls to the NRF, so the NRF's own logs are enough for them. E4 and E6 also
    arrive at the NRF; E5 goes the other way.
  * E8 never stands alone: it adds "who really connected" to the other events, which is why its fields
    sit inside the NRF event rows.
  * The simulation only uses E1, E2, E7, E8 and E9. E3-E6 would make useful extra features, for example
    discovery sweeps (E6) or s
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

KEYS = ["nf_instance_id", "window_start"]
FEATURE_COLS = [
    "id_in_inventory", "addr_in_inventory", "cert_matches_profile", "second_source_for_id",
    "orch_event_matched", "in_change_window", "diff_risk_score", "allowlist_widened", "ranges_added",
    "token_sub_matches_cert", "time_to_first_traffic_s", "new_instance_traffic_share_10m",
    "edge_is_new", "edge_policy_violation", "token_scope_vs_call_mismatch", "edge_403_ratio",
]
RISK_COLS = [
    "r_id_unknown", "r_addr_unknown", "r_cert_mismatch", "r_second_source", "r_orch_unmatched",
    "r_outside_window", "r_diff_risk", "r_allowlist_widened", "r_ranges_added", "r_token_sub_mismatch",
    "r_fast_traffic", "r_traffic_share", "r_new_edges", "r_policy_violation", "r_scope_mismatch",
    "r_denied_on_new",
]
# risk weight of each changed profile path (addresses and allow-lists high, load low)
FIELD_RISK = {
    "*new*": 6.0, "/load": 0.1, "/capacity": 0.5, "/priority": 1.0, "/heartBeatTimer": 1.0,
    "/supportedFeatures": 1.0, "/nfServices": 2.0, "/fqdn": 5.0, "/ipv4Addresses": 5.0,
    "/nfServiceEndpoints": 5.0, "/udmInfo/supiRanges": 4.0, "/amfInfo/taiList": 2.0,
    "/smfInfo/sNssaiSmfInfoList": 2.0, "/allowedNfTypes": 4.0, "/allowedNssais": 4.0,
    "/allowedOperationsPerNfType": 4.0,
}
SECOND_SOURCE_HOLD_H = 6      # "second source" stays raised for N windows (24 h in production)
MATERIAL_SCORE = 3.0          # updates below this risk are routine (load/capacity) and need no orchestration
TTFT_CAP_S = 3600.0
SPLIT_FRACTIONS = (0.5, 0.2)  # train / val share of the post-baseline period, test is the remainder


def _ns(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s).astype("datetime64[ns]")  # also handles all-empty columns


def load_raw(data_dir: str | Path) -> tuple[dict, dict]:
    d = Path(data_dir)
    meta = json.loads((d / "meta.json").read_text())
    dates = {
        "inventory": ["live_from", "known_from"], "change_feed": ["ts_start", "ts_end", "approved_from"], "nrf_events": ["ts"],
        "post_register_traffic": ["reg_ts"], "token_requests": ["window_start"], "sbi_calls": ["window_start"],
        "producer_load": ["window_start"], "labels": ["window_start"], "episodes": ["start_window"], "policy_matrix": [],
    }
    raw = {}
    for name, cols in dates.items():
        df = pd.read_csv(d / f"{name}.csv", parse_dates=cols or False)
        for c in cols:
            df[c] = _ns(df[c])
        raw[name] = df
    return raw, meta


def _diff_score(paths) -> float:
    if not isinstance(paths, str) or not paths:
        return 0.0
    return float(sum(FIELD_RISK.get(p, 1.0) for p in paths.split(";") if p))


def _event_features(raw: dict) -> pd.DataFrame:
    """Per-event (E1/E2) features, then aggregated to (instance, window)."""
    inv = raw["inventory"].set_index("nf_instance_id")
    ev = raw["nrf_events"].sort_values("ts").reset_index(drop=True).copy()
    ev["inv_fqdn"] = ev.nf_instance_id.map(inv.fqdn)
    ev["inv_ips"] = ev.nf_instance_id.map(inv.approved_ips)
    fqdn_ok = ev.profile_fqdn == ev.inv_fqdn
    ip_ok = pd.Series([isinstance(ips, str) and ip in ips.split("|") for ip, ips in zip(ev.profile_ip, ev.inv_ips)])
    known_from = ev.nf_instance_id.map(inv.known_from)  # CMDB entries can lag behind the deployment
    known = (known_from.notna() & (ev.ts >= known_from)).values
    ev["addr_in_inventory"] = (fqdn_ok.values & ip_ok.values & known).astype(int)
    ev["cert_matches_profile"] = (ev.cert_san == ev.profile_fqdn).astype(int)
    ev["diff_risk_score"] = ev.changed_paths.map(_diff_score)
    material = (ev.event_type == "REGISTER") | (ev.diff_risk_score >= MATERIAL_SCORE)

    # orchestrator event for the same instance within +/-10 minutes
    chg = raw["change_feed"]
    orch = chg[chg.kind == "orchestrator_event"][["nf_instance_id", "ts_start"]].sort_values("ts_start")
    m = pd.merge_asof(ev[["evt_id", "nf_instance_id", "ts"]], orch, by="nf_instance_id", left_on="ts",
                      right_on="ts_start", direction="nearest", tolerance=pd.Timedelta("10min"))
    ev["orch_event_matched"] = (m.ts_start.notna().values | ~material.values).astype(int)

    # maintenance calendar
    in_win = np.zeros(len(ev), bool)
    for _, w in chg[chg.kind == "maintenance_window"].iterrows():
        in_win |= ((ev.ts >= w.ts_start) & (ev.ts <= w.ts_end)).values
    ev["in_change_window"] = (in_win | ~material.values).astype(int)

    # same instance id seen with a different certificate or source address than its previous event
    g = ev.groupby("nf_instance_id")
    prev_fp, prev_src = g.cert_fp.shift(), g.src_ip.shift()
    ev["second_src"] = (((ev.cert_fp != prev_fp) & prev_fp.notna()) | ((ev.src_ip != prev_src) & prev_src.notna())).astype(int)
    ev["window_start"] = ev.ts.dt.floor("h")
    ev["allowlist_widened"] = ev.n_allowlist_added
    ev["ranges_added"] = ev.n_ranges_added

    agg = ev.groupby(KEYS).agg(
        diff_risk_score=("diff_risk_score", "max"), allowlist_widened=("allowlist_widened", "sum"),
        ranges_added=("ranges_added", "sum"), orch_event_matched=("orch_event_matched", "min"),
        in_change_window=("in_change_window", "min"), second_src=("second_src", "max"),
        addr_in_inventory=("addr_in_inventory", "last"), cert_matches_profile=("cert_matches_profile", "last"),
    ).reset_index()
    return agg


def _post_register_features(raw: dict) -> pd.DataFrame:
    p = raw["post_register_traffic"].copy()
    p["window_start"] = p.reg_ts.dt.floor("h")
    p["ttft"] = p.ttft_s.fillna(TTFT_CAP_S).clip(upper=TTFT_CAP_S)
    p["share"] = p.requests_10m / p.type_requests_10m.clip(lower=1)
    return p.groupby(KEYS).agg(time_to_first_traffic_s=("ttft", "min"),
                               new_instance_traffic_share_10m=("share", "max")).reset_index()


def _token_features(raw: dict) -> pd.DataFrame:
    t = raw["token_requests"].groupby(KEYS).agg(n_req=("n_requests", "sum"), n_bad=("n_sub_mismatch", "sum")).reset_index()
    t["token_sub_matches_cert"] = (t.n_bad == 0).astype(int)
    return t[KEYS + ["token_sub_matches_cert"]]


def _edge_features(raw: dict, baseline_end: pd.Timestamp) -> pd.DataFrame:
    c = raw["sbi_calls"].copy()
    c["edge"] = c.consumer_type + "|" + c.service + "|" + c.operation
    baseline_edges = set(c.loc[c.window_start < baseline_end, "edge"])
    # edges approved by a change ticket become part of the baseline once the change window closes
    approved: dict = {}
    chg = raw["change_feed"]
    for _, r in chg[chg.approved_edges.notna() & chg.approved_from.notna()].iterrows():
        for e in str(r.approved_edges).split(";"):
            approved[e] = min(approved.get(e, r.approved_from), r.approved_from)
    c["is_new"] = ~c.edge.isin(baseline_edges)
    ap = c.edge.map(approved)
    c.loc[ap.notna() & (c.window_start >= ap), "is_new"] = False
    allowed = set(zip(raw["policy_matrix"].service, raw["policy_matrix"].allowed_consumer_type))
    c["allowed"] = [(s, t) in allowed for s, t in zip(c.service, c.consumer_type)]
    c["violation"] = (~c.allowed) & (c.n_2xx > 0)
    c["mism_calls"] = np.where(c.token_scope_service != c.service, c.n_calls, 0)
    c["new_calls"] = np.where(c.is_new, c.n_calls, 0)
    c["new_denied"] = np.where(c.is_new, c.n_401 + c.n_403, 0)
    a = c.groupby(KEYS).agg(edge_is_new=("is_new", "sum"), edge_policy_violation=("violation", "sum"),
                            mism=("mism_calls", "sum"), calls=("n_calls", "sum"),
                            new_calls=("new_calls", "sum"), new_denied=("new_denied", "sum")).reset_index()
    a["token_scope_vs_call_mismatch"] = a.mism / a.calls.clip(lower=1)
    a["edge_403_ratio"] = np.where(a.new_calls > 0, a.new_denied / a.new_calls.clip(lower=1), 0.0)
    return a[KEYS + ["edge_is_new", "edge_policy_violation", "token_scope_vs_call_mismatch", "edge_403_ratio"]]


def build_features(raw: dict, meta: dict) -> pd.DataFrame:
    """Return one row per (instance, hour) with FEATURE_COLS plus label / subtype / episode_id."""
    baseline_end = pd.Timestamp(meta["start"]) + pd.Timedelta(days=meta["baseline_days"])
    u = (raw["producer_load"][KEYS + ["nf_type"]].drop_duplicates(KEYS)
         .sort_values(KEYS).reset_index(drop=True))
    known_from = u.nf_instance_id.map(raw["inventory"].set_index("nf_instance_id").known_from)
    u["id_in_inventory"] = (known_from.notna() & (u.window_start >= known_from.dt.floor("h"))).astype(int)

    for part in (_event_features(raw), _post_register_features(raw), _token_features(raw),
                 _edge_features(raw, baseline_end)):
        u = u.merge(part, on=KEYS, how="left")

    # state features survive until the next event; everything else is neutral without an event
    state = ["addr_in_inventory", "cert_matches_profile"]
    u[state] = u.groupby("nf_instance_id")[state].ffill().fillna(1).astype(int)
    u["second_source_for_id"] = (u.groupby("nf_instance_id")["second_src"]
                                 .transform(lambda s: s.fillna(0).rolling(SECOND_SOURCE_HOLD_H, min_periods=1).max()))
    neutral = {"orch_event_matched": 1, "in_change_window": 1, "diff_risk_score": 0.0, "allowlist_widened": 0,
               "ranges_added": 0, "token_sub_matches_cert": 1, "time_to_first_traffic_s": TTFT_CAP_S,
               "new_instance_traffic_share_10m": 0.0, "edge_is_new": 0, "edge_policy_violation": 0,
               "token_scope_vs_call_mismatch": 0.0, "edge_403_ratio": 0.0}
    u = u.fillna(neutral)

    lab = raw["labels"][KEYS + ["label", "subtype", "episode_id"]]
    u = u.merge(lab, on=KEYS, how="left")
    u["label"] = u.label.fillna(0).astype(int)
    u["subtype"] = u.subtype.fillna("normal")
    u["episode_id"] = u.episode_id.fillna("")
    cols = KEYS + ["nf_type"] + FEATURE_COLS + ["label", "subtype", "episode_id"]
    return u[cols].sort_values(KEYS).reset_index(drop=True)


def risk_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Model inputs, all oriented so that a larger value means more suspicious."""
    r = pd.DataFrame(index=df.index)
    r["r_id_unknown"] = 1 - df.id_in_inventory
    r["r_addr_unknown"] = 1 - df.addr_in_inventory
    r["r_cert_mismatch"] = 1 - df.cert_matches_profile
    r["r_second_source"] = df.second_source_for_id
    r["r_orch_unmatched"] = 1 - df.orch_event_matched
    r["r_outside_window"] = 1 - df.in_change_window
    r["r_diff_risk"] = np.log1p(df.diff_risk_score)
    r["r_allowlist_widened"] = np.log1p(df.allowlist_widened)
    r["r_ranges_added"] = np.log1p(df.ranges_added)
    r["r_token_sub_mismatch"] = 1 - df.token_sub_matches_cert
    r["r_fast_traffic"] = 1.0 / (1.0 + df.time_to_first_traffic_s / 60.0)
    r["r_traffic_share"] = df.new_instance_traffic_share_10m.clip(0, 1)
    r["r_new_edges"] = np.log1p(df.edge_is_new)
    r["r_policy_violation"] = np.log1p(df.edge_policy_violation)
    r["r_scope_mismatch"] = df.token_scope_vs_call_mismatch
    r["r_denied_on_new"] = df.edge_403_ratio
    return r[RISK_COLS].astype(float)


def split_masks(df: pd.DataFrame, meta: dict) -> dict[str, np.ndarray]:
    """Time-based split. 'train' includes the clean baseline period; val and test follow it in time."""
    start = pd.Timestamp(meta["start"])
    base, rem = meta["baseline_days"], meta["days"] - meta["baseline_days"]
    tr_end = start + pd.Timedelta(days=base + round(SPLIT_FRACTIONS[0] * rem))
    va_end = tr_end + pd.Timedelta(days=round(SPLIT_FRACTIONS[1] * rem))
    w = df.window_start
    return {"train": (w < tr_end).values, "val": ((w >= tr_end) & (w < va_end)).values, "test": (w >= va_end).values,
            "bounds": {"train_end": str(tr_end), "val_end": str(va_end)}}


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Build the feature table and print a quick summary")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--out", default="", help="optional CSV path for the feature table")
    a = ap.parse_args()
    raw_, meta_ = load_raw(a.data_dir)
    feats = build_features(raw_, meta_)
    print(f"{len(feats)} rows, {feats.label.sum()} anomalous windows")
    print(feats.groupby("subtype")[FEATURE_COLS].mean().round(2).T.to_string())
    if a.out:
        feats.to_csv(a.out, index=False)
