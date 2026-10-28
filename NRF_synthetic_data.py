#!/usr/bin/env python3
"""Synthetic NRF / SBI telemetry for "rogue or changed NF registration + new NF-to-NF call edges".

The generator writes the *raw* tables a real deployment would have (NRF access log, token log,
SCP/mesh call roll-ups, inventory and change feed). `features.py` turns them into the 14 selected
features; no feature is computed here, and the ground truth lives only in labels.csv / episodes.csv.

Raw tables written to --out (CSV):
  inventory.csv               CMDB/NFVO: approved NF instances, FQDNs, approved IPs, known_from
  change_feed.csv             orchestrator events (instance-specific) + maintenance windows
  policy_matrix.csv           (service, allowed consumer NF type): 3GPP procedures + NRF allow-lists
  nrf_events.csv              E1/E2: NFRegister / NFUpdate (profile, TLS identity, JSON-patch paths)
  post_register_traffic.csv   E9 roll-up after each NFRegister: time to first request, 10-min share
  token_requests.csv          E7: Nnrf_AccessToken requests per instance and hour
  sbi_calls.csv               E9: SCP/mesh roll-up per (hour, consumer, service, operation, token scope)
  producer_load.csv           requests received per instance and hour (defines the instance-hour universe)
  labels.csv / episodes.csv   ground truth (anomaly episodes and benign changes)
  meta.json                   start time, days, baseline length

Benign "hard negatives" are generated on purpose: autoscale-out (incl. instances whose CMDB entry lags
by 24 h), rolling upgrades, slice launches, DR failover/failback, NRF-restart mass re-registration,
certificate rotation, pod reschedules (new source IP), a new NF type going live (new legitimate call
edges), 6-hour feature trials (new edge answered 2xx but absent from the stale policy matrix),
late orchestrator events (8 % are logged more than 10 min off) and post-incident remediation.


Event tags E1-E9
----------------
E1-E9 are this project's own shorthand, not 3GPP names. Each maps to a 3GPP operation, except E8,
which is the TLS layer underneath every SBI connection. 
They represent the SBI protocol events that can be used in real networks to build the features.
and they are used to shape the row tables like what you would get after collecting those events from real networks.
 
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
    discovery sweeps (E6) or subscription callbacks pointing outside your domain (E4).


Anomaly episodes (5 subtypes): rogue_impostor, duplicate_id, hijack, privilege_widening, lateral_edge.
Type	            What is attacked	                        NRF event?	    Identity looks clean?
rogue_impostor	    A new fake NF joins the registry	        REGISTER	    Sometimes (reserved variant)
duplicate_id	    A real NF ID is registered a second time	REGISTER	    No
hijack	            A real NF address is changed	            UPDATE	        Sometimes (stealth variant)
privilege_widening	A real producer allow-list is widened	    UPDATE	        Yes
lateral_edge	    A real NF calls a service it should not	    None	        Yes

Usage:  python synthetic_data.py --out data --days 45 --baseline-days 10 --episodes 110 --seed 7
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

START = pd.Timestamp("2026-01-05 00:00:00")  # a Monday
H1 = pd.Timedelta(hours=1)

NF_COUNTS = {"AMF": 6, "SMF": 6, "UDM": 4, "AUSF": 3, "UDR": 3, "PCF": 3, "NSSF": 2, "UPF": 6}
AUTOSCALE_EXTRA = {"AMF": [7, 8], "SMF": [7, 8], "UDM": [5]}
NEF_IDS = [1, 2]
TYPE_IDX = {t: i for i, t in enumerate(["AMF", "SMF", "UDM", "AUSF", "UDR", "PCF", "NSSF", "UPF", "NEF"])}

# consumer NF type -> [(service, operation template, mean calls/hour per instance)]
EDGES = {
    "AMF": [
        ("Nausf_UEAuthentication", "POST /ue-authentications", 400),
        ("Nudm_UECM", "PUT /{ueId}/registrations/amf-3gpp-access", 500),
        ("Nudm_SDM", "GET /{supi}/am-data", 500),
        ("Nsmf_PDUSession", "POST /sm-contexts", 300),
        ("Npcf_AMPolicyControl", "POST /policies", 300),
        ("Nnssf_NSSelection", "GET /network-slice-information", 250),
    ],
    "SMF": [
        ("Nudm_SDM", "GET /{supi}/sm-data", 300),
        ("Nudm_UECM", "PUT /{ueId}/registrations/smf-registrations/{pduSessionId}", 300),
        ("Npcf_SMPolicyControl", "POST /sm-policies", 300),
        ("Namf_Communication", "POST /ue-contexts/{ueContextId}/n1-n2-messages", 250),
    ],
    "AUSF": [("Nudm_UEAuthentication", "POST /{supi}/security-information/generate-auth-data", 400)],
    "UDM": [("Nudr_DR", "GET /subscription-data/{ueId}/provisioned-data", 800)],
    "PCF": [("Nudr_DR", "GET /policy-data/ues/{ueId}/sm-data", 300)],
    "NEF": [
        ("Nudm_EventExposure", "POST /{ueIdentity}/subscriptions", 60),
        ("Npcf_PolicyAuthorization", "POST /app-sessions", 60),
    ],
}
SERVICE_PRODUCER = {
    "Nausf_UEAuthentication": "AUSF", "Nudm_UECM": "UDM", "Nudm_SDM": "UDM", "Nudm_UEAuthentication": "UDM",
    "Nudm_EventExposure": "UDM", "Nsmf_PDUSession": "SMF", "Npcf_AMPolicyControl": "PCF",
    "Npcf_SMPolicyControl": "PCF", "Npcf_PolicyAuthorization": "PCF", "Nnssf_NSSelection": "NSSF",
    "Namf_Communication": "AMF", "Nudr_DR": "UDR",
}
SERVICE_OP = {}
ALLOWED = {}  # service -> allowed consumer types
for _c, _edges in EDGES.items():
    for _s, _op, _ in _edges:
        SERVICE_OP.setdefault(_s, _op)
        ALLOWED.setdefault(_s, set()).add(_c)
PRODUCER_LOAD = {"AMF": 1000, "SMF": 800, "UDM": 3000, "AUSF": 1200, "UDR": 2000, "PCF": 900,
                 "NSSF": 500, "UPF": 50, "NEF": 100}
CONSUMER_TYPES = ["AMF", "SMF", "PCF", "NEF", "UPF", "AUSF", "UDM"]
SUBTYPES = ["rogue_impostor", "duplicate_id", "hijack", "privilege_widening", "lateral_edge"]
SUBTYPE_P = [0.25, 0.15, 0.20, 0.15, 0.25]


def _hex(s: str, n: int = 16) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:n]


class Simulator:
    def __init__(self, days: int, baseline_days: int, n_episodes: int, seed: int):
        self.rng = np.random.default_rng(seed)
        self.days, self.baseline_days, self.n_episodes = days, baseline_days, n_episodes
        self.H, self.base_h = days * 24, baseline_days * 24
        hours = np.arange(self.H)
        dow = (hours // 24) % 7
        self.diurnal = (0.75 + 0.25 * np.sin(2 * np.pi * ((hours % 24) - 9) / 24)) * np.where(dow >= 5, 0.85, 1.0)
        self.events, self.changes, self.post, self.load_rows = [], [], [], []
        self.call_frames, self.token_frames = [], []
        self.lab: dict = {}
        self.episodes: list = []
        self._evt = self._chg = 0
        self.maint = [(d * 24 + 1, d * 24 + 5) for d in range(days) if d % 7 in (1, 3)]  # Tue/Thu 01-05h
        self.insts: dict = {}
        self.rot: dict = {}
        self.real: list = []

    # ---------------------------------------------------------------- helpers
    def T(self, h: float) -> pd.Timestamp:
        return START + pd.Timedelta(hours=float(h))

    def win(self, hs) -> pd.DatetimeIndex:
        return START + pd.to_timedelta(np.atleast_1d(hs), unit="h")

    def maint_time(self, lo: float, hi: float) -> float:
        cands = [w for w in self.maint if w[0] >= lo and w[1] <= hi]
        if not cands:  # no window in range: take the closest one that still fits the overall horizon
            mid = (lo + hi) / 2
            ok = [w for w in self.maint if w[1] <= self.H - 1] or self.maint
            cands = [min(ok, key=lambda w: abs(w[0] - mid))]
        w = cands[int(self.rng.integers(len(cands)))]
        return w[0] + self.rng.random() * (w[1] - w[0] - 0.5)

    def fp_at(self, inst: dict, h: float) -> str:
        fp = inst["fp"]
        for rh, rfp in self.rot.get(inst["id"], []):
            if rh <= h:
                fp = rfp
        return fp

    def mark(self, iid: str, h0: int, h1: int, label: int, subtype: str, ep: str = ""):
        for h in range(int(h0), min(int(h1), self.H)):
            cur = self.lab.get((iid, h))
            if cur is not None and cur[0] == 1 and label == 0:
                continue  # anomaly labels win over benign ones
            self.lab[(iid, h)] = (label, subtype, ep)

    def ev(self, h, iid, etype, ntype, src, san, fp, fqdn, ip, changed="", ranges=0, allow=0,
           priority=10, capacity=100) -> str:
        self._evt += 1
        eid = f"E{self._evt:06d}"
        self.events.append(dict(evt_id=eid, ts=self.T(h), nf_instance_id=iid, event_type=etype, nf_type=ntype,
                                src_ip=src, cert_san=san, cert_fp=fp, profile_fqdn=fqdn, profile_ip=ip,
                                priority=priority, capacity=capacity, changed_paths=changed,
                                n_ranges_added=int(ranges), n_allowlist_added=int(allow)))
        return eid

    def legit_ev(self, inst, h, etype, changed="", ranges=0, allow=0, ip=None) -> str:
        ip = ip or inst["ip"]
        return self.ev(h, inst["id"], etype, inst["type"], ip, inst["fqdn"], self.fp_at(inst, h), inst["fqdn"], ip,
                       changed, ranges, allow)

    def add_change(self, h, iid, kind="orchestrator_event", approved_edges="", approved_from=None):
        self._chg += 1
        lag = float(self.rng.uniform(12, 40)) if self.rng.random() < 0.08 else float(self.rng.uniform(0, 4))
        start = self.T(h) - pd.Timedelta(minutes=lag)  # 8 % of orchestrator events are logged >10 min away
        self.changes.append(dict(change_id=f"C{self._chg:05d}", kind=kind, nf_instance_id=iid, ts_start=start,
                                 ts_end=self.T(h) + pd.Timedelta(minutes=1), approved_edges=approved_edges,
                                 approved_from=approved_from))

    def add_post(self, eid, iid, h, ntype, ttft, share):
        type_req = PRODUCER_LOAD[ntype] * NF_COUNTS.get(ntype, 2) * self.diurnal[min(int(h), self.H - 1)] / 6
        type_req = int(type_req * self.rng.lognormal(0, 0.1))
        self.post.append(dict(evt_id=eid, nf_instance_id=iid, reg_ts=self.T(h), ttft_s=ttft,
                              requests_10m=int(share * type_req), type_requests_10m=type_req))

    def add_calls(self, hs, iid, ctype, service, op, n, token_service=None, p401=0.0005, p403=0.0, p5xx=0.002):
        hs, n = np.atleast_1d(hs), np.atleast_1d(n).astype(int)
        n401, n403, n5 = (self.rng.binomial(n, p) for p in (p401, p403, p5xx))
        n2 = np.clip(n - n401 - n403 - n5, 0, None)
        self.call_frames.append(pd.DataFrame(dict(
            window_start=self.win(hs), nf_instance_id=iid, consumer_type=ctype, service=service, operation=op,
            token_scope_service=token_service or service, n_calls=n, n_2xx=n2, n_401=n401, n_403=n403, n_5xx=n5)))

    def add_tokens(self, hs, iid, n_req, n_bad):
        hs = np.atleast_1d(hs)
        self.token_frames.append(pd.DataFrame(dict(
            window_start=self.win(hs), nf_instance_id=iid, n_requests=np.atleast_1d(n_req).astype(int),
            n_sub_mismatch=np.atleast_1d(n_bad).astype(int))))

    def add_load(self, hs, iid, ntype, mult=1.0):
        hs = np.atleast_1d(hs)
        lam = PRODUCER_LOAD[ntype] * self.diurnal[hs] * mult * self.rng.lognormal(0, 0.1, len(hs))
        self.load_rows.append(pd.DataFrame(dict(window_start=self.win(hs), nf_instance_id=iid, nf_type=ntype,
                                                n_requests_received=self.rng.poisson(lam))))

    @staticmethod
    def violating_edge(rng, ctype):
        cands = [s for s in SERVICE_OP if ctype not in ALLOWED[s]]
        s = cands[int(rng.integers(len(cands)))]
        return s, SERVICE_OP[s]

    # ---------------------------------------------------------------- instances
    def _mk(self, ntype, k, live_h, kind):
        iid = f"{ntype.lower()}-{k:02d}"
        t = TYPE_IDX[ntype]
        inst = dict(id=iid, type=ntype, fqdn=f"{iid}.5gc.mnc001.mcc001.3gppnetwork.org", ip=f"10.{10 + t}.0.{k}",
                    dr_ip=f"10.{110 + t}.0.{k}", fp=_hex(iid), live_h=int(live_h), kind=kind)
        self.insts[iid] = inst
        return inst

    def build_instances(self):
        for t, n in NF_COUNTS.items():
            for k in range(1, n + 1):
                self._mk(t, k, 0, "base")
        lo, hi = self.base_h + 24, self.H - 48
        for t, ks in AUTOSCALE_EXTRA.items():
            for k in ks:
                self._mk(t, k, int(self.maint_time(lo, hi)), "autoscale")
        for t, k in [("AMF", 9), ("SMF", 9), ("UDM", 6), ("AUSF", 4), ("PCF", 4)]:
            self._mk(t, k, 24 * 365 * 5, "reserved")  # CMDB entries that are reserved but never deployed
        for n, inst in enumerate(i for i in self.insts.values() if i["kind"] == "autoscale"):
            if n < 2:
                inst["known_h"] = inst["live_h"] + 24  # CMDB updated a day late
        nef_day = self.baseline_days + 5
        nef_h = self.maint_time(nef_day * 24, self.H - 48)
        for k in NEF_IDS:
            self._mk("NEF", k, int(nef_h), "nef")
        # certificate rotations are scheduled first so every later event sees the right fingerprint
        base = [i for i in self.insts.values() if i["kind"] == "base"]
        for idx in self.rng.choice(len(base), size=min(15, len(base) * 2), replace=True):
            inst = base[int(idx)]
            h = float(self.rng.uniform(self.base_h + 12, self.H - 12))
            self.rot.setdefault(inst["id"], []).append((h, _hex(inst["id"] + f"-rot{h:.2f}")))
        for v in self.rot.values():
            v.sort()

    def live(self, h: float, kinds=None):
        return [i for i in self.insts.values() if i["live_h"] <= h and (kinds is None or i["kind"] in kinds)]

    # ---------------------------------------------------------------- normal behaviour
    def normal_traffic(self, inst):
        h0 = inst["live_h"]
        hrs = np.arange(h0, self.H)
        if len(hrs) == 0:
            return
        ramp = np.minimum(1.0, (hrs - h0 + 1) / 6) if inst["kind"] != "base" else 1.0
        self.add_load(hrs, inst["id"], inst["type"], mult=ramp)
        for service, op, base in EDGES.get(inst["type"], []):
            lam = base * self.diurnal[hrs] * ramp * self.rng.lognormal(0, 0.1, len(hrs))
            self.add_calls(hrs, inst["id"], inst["type"], service, op, self.rng.poisson(lam))
        if inst["type"] in EDGES:
            bad = (self.rng.random(len(hrs)) < 0.003).astype(int)  # rare benign misconfiguration noise
            self.add_tokens(hrs, inst["id"], self.rng.poisson(6, len(hrs)), bad)

    def normal_events(self):
        rng = self.rng
        self.real = [i for i in self.insts.values() if i["kind"] != "reserved"]
        # initial registrations (all orchestrated)
        for inst in self.real:
            if inst["kind"] == "base":
                h = rng.uniform(0.02, 0.6)
                eid = self.legit_ev(inst, h, "REGISTER", "*new*")
                self.add_change(h, inst["id"])
                self.add_post(eid, inst["id"], h, inst["type"], float(rng.uniform(5, 60)),
                              1 / NF_COUNTS[inst["type"]])
            else:
                h = inst["live_h"] + rng.uniform(0.05, 0.5)
                eid = self.legit_ev(inst, h, "REGISTER", "*new*")
                approved, appr_from = "", None
                sub = "benign_autoscale"
                if inst["kind"] == "nef":
                    sub = "benign_nf_introduction"
                    approved = ";".join(f"NEF|{s}|{op}" for s, op, _ in EDGES["NEF"])
                    appr_from = self.T(h + 6)  # edges are learned only after the change window closes
                self.add_change(h, inst["id"], approved_edges=approved, approved_from=appr_from)
                self.add_post(eid, inst["id"], h, inst["type"], float(rng.uniform(60, 900)), float(rng.uniform(0.0, 0.06)))
                if inst.get("known_h"):
                    self.mark(inst["id"], int(h), int(h) + 24, 0, "benign_cmdb_lag")
                self.mark(inst["id"], int(h), int(h) + (6 if inst["kind"] == "nef" else 1), 0, sub)
        # routine load/capacity updates (not orchestrated, low risk)
        for inst in self.real:
            n = rng.poisson(0.8 * (self.H - inst["live_h"]) / 24)
            for h in rng.uniform(inst["live_h"] + 0.7, self.H - 0.01, n):
                self.legit_ev(inst, h, "UPDATE", "/load" if rng.random() < 0.7 else "/load;/capacity")
        # certificate rotations: same SAN, new fingerprint
        for iid, rots in self.rot.items():
            inst = self.insts[iid]
            for h, _ in rots:
                self.legit_ev(inst, h + 0.001, "UPDATE", "")
                if rng.random() < 0.7:
                    self.add_change(h, iid)
                self.mark(iid, int(h), int(h) + 1, 0, "benign_cert_rotation")
        # rolling upgrades in maintenance windows
        for _ in range(45):
            h = self.maint_time(1, self.H)
            cands = self.live(h, {"base", "autoscale"})
            inst = cands[int(rng.integers(len(cands)))]
            eid = self.legit_ev(inst, h, "REGISTER", "/supportedFeatures" if rng.random() < 0.6 else "")
            self.add_change(h, inst["id"])
            self.add_post(eid, inst["id"], h, inst["type"], float(rng.uniform(30, 300)),
                          float(rng.uniform(0.6, 1.1)) / NF_COUNTS[inst["type"]])
            self.mark(inst["id"], int(h), int(h) + 1, 0, "benign_rolling_upgrade")
        # slice launches
        for _ in range(10):
            h = self.maint_time(self.base_h + 12, self.H - 6)
            cands = [i for i in self.live(h, {"base", "autoscale"}) if i["type"] in ("AMF", "SMF", "UDM", "PCF")]
            inst = cands[int(rng.integers(len(cands)))]
            path = "/amfInfo/taiList" if inst["type"] == "AMF" else "/smfInfo/sNssaiSmfInfoList"
            self.legit_ev(inst, h, "UPDATE", path, ranges=int(rng.integers(1, 4)), allow=int(rng.integers(0, 2)))
            self.add_change(h, inst["id"])
            self.mark(inst["id"], int(h), int(h) + 1, 0, "benign_slice_launch")
        # DR failover + failback
        for _ in range(5):
            h = float(rng.uniform(self.base_h + 24, self.H - 12))
            inst = self.live(h, {"base"})[int(rng.integers(len(self.live(h, {"base"}))))]
            for hh, ip in ((h, inst["dr_ip"]), (h + float(rng.uniform(2, 5)), inst["ip"])):
                eid = self.legit_ev(inst, hh, "REGISTER", "/ipv4Addresses", ip=ip)
                self.add_change(hh, inst["id"])
                self.add_post(eid, inst["id"], hh, inst["type"], float(rng.uniform(15, 120)),
                              1 / NF_COUNTS[inst["type"]])
                self.mark(inst["id"], int(hh), int(hh) + 1, 0, "benign_dr_failover")
        # NRF restart: everybody re-registers, nothing was orchestrated for the instances
        for _ in range(3):
            h = int(rng.uniform(self.base_h + 24, self.H - 24))
            for inst in self.live(h + 1):
                t = h + float(rng.uniform(0.0, 0.08))
                eid = self.legit_ev(inst, t, "REGISTER", "")
                self.add_post(eid, inst["id"], t, inst["type"], float(rng.uniform(1, 4)),
                              1 / NF_COUNTS.get(inst["type"], 2))
                self.mark(inst["id"], h, h + 1, 0, "benign_nrf_resync")

        # pod reschedules: heartbeat from a new source IP inside the pool, same profile and certificate
        for _ in range(40):
            h = float(rng.uniform(self.base_h, self.H - 1))
            cands = self.live(h, {"base", "autoscale"})
            inst = cands[int(rng.integers(len(cands)))]
            src = f"10.{10 + TYPE_IDX[inst['type']]}.1.{int(rng.integers(1, 250))}"
            self.ev(h, inst["id"], "UPDATE", inst["type"], src, inst["fqdn"], self.fp_at(inst, h), inst["fqdn"],
                    inst["ip"], "/load")
            self.mark(inst["id"], int(h), int(h) + 1, 0, "benign_pod_reschedule")
        # 6-hour feature trials: new edge, 2xx, correct token scope, but missing from the stale policy matrix
        for _ in range(8):
            h = int(rng.uniform(self.base_h + 12, self.H - 12))
            cands = [i for i in self.live(h, {"base"}) if i["type"] in ("AMF", "SMF")]
            inst = cands[int(rng.integers(len(cands)))]
            service, op = self.violating_edge(rng, inst["type"])
            hrs = np.arange(h, h + 6)
            self.add_calls(hrs, inst["id"], inst["type"], service, op, rng.poisson(rng.uniform(30, 150), len(hrs)))
            self.add_change(h, inst["id"])
            self.mark(inst["id"], h, h + 6, 0, "benign_feature_trial")

    # ---------------------------------------------------------------- anomalies
    def _lateral_calls(self, hs, iid, ctype, gap: bool, strength: float, token_mismatch_p=0.6):
        service, op = self.violating_edge(self.rng, ctype)
        own = EDGES[ctype][0][0] if ctype in EDGES else "Nudm_SDM"
        tok = own if (self.rng.random() < token_mismatch_p and own != service) else service
        n = self.rng.poisson(strength, len(hs))
        if gap:   # enforcement gap: requests succeed
            self.add_calls(hs, iid, ctype, service, op, n, tok, p401=0.01, p403=0.03)
        else:     # probing: mostly denied
            self.add_calls(hs, iid, ctype, service, op, n, tok, p401=0.05, p403=0.9)

    def _bad_tokens(self, hs, iid, p_bad):
        bad = self.rng.poisson(3, len(hs)) if self.rng.random() < p_bad else np.zeros(len(hs), int)
        self.add_tokens(hs, iid, self.rng.poisson(12, len(hs)) + bad, bad)

    def inject(self):
        rng = self.rng
        kinds = rng.choice(SUBTYPES, size=self.n_episodes, p=SUBTYPE_P)
        times = np.sort(rng.uniform(self.base_h + 6, self.H - 14, self.n_episodes))
        busy: dict = {}
        for n, (kind, t) in enumerate(zip(kinds, times)):
            kind, ep = str(kind), f"EP{n:03d}"
            if rng.random() < 0.25 and kind in ("rogue_impostor", "duplicate_id", "privilege_widening"):
                t = self.maint_time(max(self.base_h + 6, t - 48), min(self.H - 14, t + 48))  # camouflage
            d = int(rng.integers(2, 7))
            hs = int(t)
            hrs = np.arange(hs, min(hs + d, self.H))
            getattr(self, f"_inj_{kind}")(ep, t, hrs, busy)
            self.episodes.append(dict(episode_id=ep, subtype=kind, start_window=self.T(hs)))

    def _pick(self, busy, hrs, types=None, kinds=("base",)):
        cands = [i for i in self.live(hrs[0], set(kinds)) if types is None or i["type"] in types]
        rng = self.rng
        for _ in range(30):
            inst = cands[int(rng.integers(len(cands)))]
            if all(hrs[-1] + 1 < a or hrs[0] > b + 1 for a, b in busy.get(inst["id"], [])):
                busy.setdefault(inst["id"], []).append((hrs[0], hrs[-1] + 1))
                return inst
        busy.setdefault(inst["id"], []).append((hrs[0], hrs[-1] + 1))
        return inst

    def _inj_rogue_impostor(self, ep, t, hrs, busy):
        rng = self.rng
        ntype = str(rng.choice(["SMF", "UDM", "AUSF", "UDR", "PCF"]))
        iid = f"{ntype.lower()}-{int(rng.integers(0x1000, 0xFFFF)):04x}"
        variant = str(rng.choice(["noisy", "stealth", "reserved"], p=[0.35, 0.3, 0.35]))
        stealth = variant != "noisy"
        fqdn = f"{iid}.5gc.mnc001.mcc001.3gppnetwork.org" if stealth else f"{iid}.lab.example.net"
        ip = f"10.{int(rng.integers(200, 250))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 254))}"
        san = fqdn if rng.random() < (0.5 if stealth else 0.3) else str(rng.choice(["localhost", "nrf.internal", "pod-7f3a"]))
        if variant == "reserved":  # squats a reserved CMDB identity and its approved address: only orchestration is missing
            r = [i for i in self.insts.values() if i["kind"] == "reserved"]
            r = r[int(rng.integers(len(r)))]
            ntype, iid, fqdn, ip = r["type"], r["id"], r["fqdn"], r["ip"]
            san = fqdn if rng.random() < 0.6 else "localhost"
        eid = self.ev(t, iid, "REGISTER", ntype, ip, san, _hex(iid + f"x{ep}"), fqdn, ip, "*new*",
                      ranges=int(rng.integers(1, 4)) if rng.random() < 0.6 else 0,
                      allow=int(rng.integers(1, 3)) if rng.random() < 0.3 else 0, priority=1, capacity=65000)
        self.add_post(eid, iid, t, ntype, float(rng.uniform(120, 900) if stealth else rng.uniform(3, 90)),
                      float(rng.uniform(0.02, 0.12) if stealth else rng.uniform(0.2, 0.6)))
        self.add_load(hrs, iid, ntype, mult=0.1 if stealth else 0.4)
        self._bad_tokens(hrs, iid, 0.45)
        if ntype in EDGES:  # mimic normal consumer edges at low volume
            for service, op, _ in EDGES[ntype]:
                self.add_calls(hrs, iid, ntype, service, op, rng.poisson(30, len(hrs)))
        if rng.random() < (0.35 if stealth else 0.65):
            self._lateral_calls(hrs, iid, ntype, gap=rng.random() < 0.6, strength=15 if stealth else 60)
        self.mark(iid, hrs[0], hrs[-1] + 1, 1, "rogue_impostor", ep)

    def _inj_duplicate_id(self, ep, t, hrs, busy):
        rng = self.rng
        inst = self._pick(busy, hrs, types={"AMF", "SMF", "UDM", "AUSF", "UDR", "PCF"})
        ip = f"10.{int(rng.integers(200, 250))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 254))}"
        fqdn = inst["fqdn"] if rng.random() < 0.5 else inst["fqdn"].replace("5gc", "5gc-b")
        san = fqdn if rng.random() < 0.5 else "localhost"
        eid = self.ev(t, inst["id"], "REGISTER", inst["type"], ip, san, _hex(inst["id"] + "dup"), fqdn, ip,
                      "/ipv4Addresses;/nfServiceEndpoints", priority=1, capacity=65000)
        self.add_post(eid, inst["id"], t, inst["type"], float(rng.uniform(5, 120)), float(rng.uniform(0.1, 0.4)))
        self._bad_tokens(hrs, inst["id"], 0.4)
        if rng.random() < 0.3:
            self._lateral_calls(hrs, inst["id"], inst["type"], gap=True, strength=40)
        self.mark(inst["id"], hrs[0], hrs[-1] + 1, 1, "duplicate_id", ep)
        self._remediate(inst, hrs[-1] + 1, "/ipv4Addresses;/nfServiceEndpoints")

    def _inj_hijack(self, ep, t, hrs, busy):
        rng = self.rng
        inst = self._pick(busy, hrs, types={"AMF", "SMF", "UDM", "AUSF", "UDR", "PCF", "NSSF"})
        stealth = rng.random() < 0.4
        ip = inst["dr_ip"] if stealth else f"10.{int(rng.integers(200, 250))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 254))}"
        fqdn = inst["fqdn"] if (stealth or rng.random() < 0.5) else inst["fqdn"].replace("5gc", "5gc-x")
        san = inst["fqdn"] if (stealth or rng.random() < 0.7) else "localhost"
        fp = self.fp_at(inst, t) if (stealth or rng.random() < 0.7) else _hex(inst["id"] + "hj")
        self.ev(t, inst["id"], "UPDATE", inst["type"], ip, san, fp, fqdn, ip,
                "/ipv4Addresses" if fqdn == inst["fqdn"] else "/fqdn;/ipv4Addresses")
        self._bad_tokens(hrs, inst["id"], 0.3)
        if rng.random() < 0.25:
            self._lateral_calls(hrs, inst["id"], inst["type"], gap=rng.random() < 0.5, strength=30)
        self.mark(inst["id"], hrs[0], hrs[-1] + 1, 1, "hijack", ep)
        self._remediate(inst, hrs[-1] + 1, "/ipv4Addresses")

    def _inj_privilege_widening(self, ep, t, hrs, busy):
        rng = self.rng
        prod = self._pick(busy, hrs, types={"UDM", "UDR", "AUSF", "PCF"})
        ranges = int(rng.integers(1, 4)) if rng.random() < 0.5 else 0
        path = "/allowedNfTypes" + (";/udmInfo/supiRanges" if ranges else "")
        self.legit_ev(prod, t, "UPDATE", path, ranges=ranges, allow=int(rng.integers(1, 5)))
        self.mark(prod["id"], hrs[0], hrs[0] + 1, 1, "privilege_widening", ep)
        services = [s for s, p in SERVICE_PRODUCER.items() if p == prod["type"]]
        service = str(rng.choice(services))
        ctypes = [c for c in CONSUMER_TYPES if c not in ALLOWED[service] and c != "NEF"]  # NEF goes live late
        ctype = str(rng.choice(ctypes))
        cinst = self._pick(busy, hrs, types={ctype}, kinds=("base", "autoscale"))
        own = EDGES[ctype][0][0] if ctype in EDGES else "Nudm_SDM"
        tok = own if (rng.random() < 0.5 and own != service) else service
        self.add_calls(hrs, cinst["id"], ctype, service, SERVICE_OP[service], rng.poisson(rng.uniform(30, 300), len(hrs)),
                       tok, p401=0.01, p403=0.02)
        self.mark(cinst["id"], hrs[0], hrs[-1] + 1, 1, "privilege_widening", ep)
        self._remediate(prod, hrs[-1] + 1, path)

    def _inj_lateral_edge(self, ep, t, hrs, busy):
        rng = self.rng
        ctype = str(rng.choice(["AMF", "SMF", "PCF", "UDM", "AUSF", "UPF"]))
        inst = self._pick(busy, hrs, types={ctype})
        gap = rng.random() < 0.55
        slow = rng.random() < 0.3  # low-and-slow: a handful of calls per hour
        strength = float(rng.uniform(3, 12) if slow else (rng.uniform(30, 400) if gap else rng.uniform(20, 150)))
        self._lateral_calls(hrs, inst["id"], ctype, gap=gap, strength=strength)
        if rng.random() < 0.3:
            self.add_tokens(hrs, inst["id"], rng.poisson(6, len(hrs)) + 2, np.full(len(hrs), 2))
        self.mark(inst["id"], hrs[0], hrs[-1] + 1, 1, "lateral_edge", ep)

    def _remediate(self, inst, h, path):
        """Operator restores the legitimate profile (orchestrated): a benign 'remediation' window."""
        if h >= self.H - 1:
            return
        t = h + float(self.rng.uniform(0.05, 0.4))
        self.legit_ev(inst, t, "UPDATE", path)
        self.add_change(t, inst["id"])
        self.mark(inst["id"], int(t), int(t) + 1, 0, "benign_remediation")

    # ---------------------------------------------------------------- output
    def run(self, out: Path):
        self.build_instances()
        for inst in self.insts.values():
            self.normal_traffic(inst)
        self.normal_events()
        self.inject()
        out.mkdir(parents=True, exist_ok=True)
        for s, e in self.maint:
            self.changes.append(dict(change_id=f"M{s}", kind="maintenance_window", nf_instance_id="*", ts_start=self.T(s),
                                     ts_end=self.T(e), approved_edges="", approved_from=None))
        inv = pd.DataFrame([dict(nf_instance_id=i["id"], nf_type=i["type"], fqdn=i["fqdn"],
                                 approved_ips=f"{i['ip']}|{i['dr_ip']}", live_from=self.T(i["live_h"]),
                                 known_from=self.T(i.get("known_h", 0)))
                            for i in self.insts.values()])
        events = pd.DataFrame(self.events).sort_values("ts")
        load = pd.concat(self.load_rows, ignore_index=True).sort_values(["nf_instance_id", "window_start"])
        labels = pd.DataFrame([dict(nf_instance_id=k[0], window_start=self.T(k[1]), label=v[0], subtype=v[1], episode_id=v[2])
                               for k, v in self.lab.items()])
        policy = pd.DataFrame([dict(service=s, allowed_consumer_type=c) for s, cs in ALLOWED.items() for c in sorted(cs)])
        tables = {
            "inventory": inv, "change_feed": pd.DataFrame(self.changes), "policy_matrix": policy,
            "nrf_events": events, "post_register_traffic": pd.DataFrame(self.post),
            "token_requests": pd.concat(self.token_frames, ignore_index=True),
            "sbi_calls": pd.concat(self.call_frames, ignore_index=True), "producer_load": load,
            "labels": labels, "episodes": pd.DataFrame(self.episodes),
        }
        for name, df in tables.items():
            df.to_csv(out / f"{name}.csv", index=False)
        meta = dict(start=str(START), days=self.days, baseline_days=self.baseline_days, window="1h",
                    n_events=len(events), n_episodes=len(self.episodes))
        (out / "meta.json").write_text(json.dumps(meta, indent=2))
        return tables, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data")
    ap.add_argument("--days", type=int, default=45)
    ap.add_argument("--baseline-days", type=int, default=10, help="clean period used to learn the edge baseline")
    ap.add_argument("--episodes", type=int, default=110, help="number of anomaly episodes injected after the baseline")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    tables, meta = Simulator(a.days, a.baseline_days, a.episodes, a.seed).run(Path(a.out))
    lab = tables["labels"]
    print(f"wrote {len(tables)} tables to {a.out}/  ({meta['n_events']} NRF events, "
          f"{len(tables['sbi_calls'])} call roll-ups)")
    print(lab.groupby("subtype").size().sort_values(ascending=False).to_string())


if __name__ == "__main__":
    main()
