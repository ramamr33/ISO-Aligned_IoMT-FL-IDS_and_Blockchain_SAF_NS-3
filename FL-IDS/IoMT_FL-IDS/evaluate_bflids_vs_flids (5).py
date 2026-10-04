#!/usr/bin/env python3
"""
Same-traffic detection comparison: FL-IDS (Rajab et al.) vs BFLIDS (Begum et al.)
================================================================================
Reads the per-window detection logs written by bflids_compare (--detLog) and
computes precision / recall / F1 / FPR / accuracy for every detector on the SAME
windows (prequential: each window is scored by models trained on earlier windows
only).

Detectors evaluated
  bflids_cnn        BFLIDS CNN probability >= 0.5           (rows with bflids_round >= 1)
  flids_classifier  FL-IDS logistic FedAvg prob >= 0.5      (rows with flids_round  >= 1)
  wasi_fixed        on-board wASI (fixed per-device ref) >= 25
  flids_fused       wasi_fixed OR flids_classifier          (the deployed FL-IDS rule)
  wasi_perflow      wASI recomputed with a genuine per-flow baseline >= 25
                    (only if --baseline benign logs are given)

Usage
  python3 evaluate_bflids_vs_flids.py --runs attack_s*.csv \
          [--benign benign_s*.csv] [--baseline benign_s1.csv] \
          [--label targeted|global] [--out results]

  --runs      detection logs from attack runs (e.g. --detector=none)
  --benign    detection logs from attack-free runs (--attackType=none) -> FPR
  --baseline  benign log(s) used to build per-flow normal baselines for wasi_perflow
"""
import argparse, glob, os
import numpy as np
import pandas as pd

WEIGHTS = {"WIP": (0.4, 0.3, 0.2, 0.1), "SHS": (0.2, 0.2, 0.3, 0.3)}  # TRR, PLR, NDI, JVI


REQUIRED = {"seed", "flow_id", "src", "dst", "owner_device", "label_global", "label_targeted",
            "throughput_kbps", "mean_delay_s", "mean_jitter_s", "loss_pct"}
BFLIDS_COLS = {"bflids_round", "bflids_prob"}
FLIDS_COLS = {"flids_round", "flids_wasi_fixed", "flids_lr_prob"}


def load(patterns, what="--runs"):
    patterns = [p.strip() for p in patterns if p.strip()]
    # Round/mitigation logs (*_rounds.csv) share the same name stem; never treat them as detection logs
    files = sorted({f for p in patterns for f in glob.glob(p) if not f.endswith("_rounds.csv")})
    if not files:
        raise SystemExit(f"ERROR: no files matched {what} {patterns} in {os.getcwd()}\n"
                         f"       Check with:  ls -l *.csv   (or give the full path to the logs)")
    for f in files:
        missing = REQUIRED - set(pd.read_csv(f, nrows=0).columns)
        if missing:
            raise SystemExit(f"ERROR: {f} is not a detection log from the FL-IDS/BFLIDS programs "
                             f"(missing columns: {sorted(missing)})")
    print(f"{what}: {len(files)} file(s): {', '.join(os.path.basename(f) for f in files)}")
    dfs = []
    for f in files:
        d = pd.read_csv(f)
        d["file"] = os.path.basename(f)
        dfs.append(d)
    return pd.concat(dfs, ignore_index=True)


def flow_key(df):
    # flow identity that is stable across runs (flow IDs can be reassigned)
    return df["src"].astype(str) + ">" + df["dst"].astype(str)


def per_flow_baseline(bdf, window=1):
    bdf = aggregate_windows(bdf, window)
    bdf["key"] = flow_key(bdf)
    return bdf.groupby("key").agg(T=("throughput_kbps", "mean"), D=("mean_delay_s", "mean"),
                                  J=("mean_jitter_s", "mean"), L=("loss_pct", "mean"))


def wasi_perflow(df, base):
    df = df.copy()
    df["key"] = flow_key(df)
    df = df.join(base, on="key")
    eps = 1e-12
    clip = lambda x: np.clip(x, 0, 100)
    trr = clip(100 * (df["T"] - df["throughput_kbps"]) / (df["T"] + eps))
    plr = clip(df["loss_pct"])                                   # Eq. 2: PLR = 100 - PDR
    ndi = clip(100 * (df["mean_delay_s"] - df["D"]) / (df["D"] + eps))
    jvi = clip(100 * (df["mean_jitter_s"] - df["J"]).abs() / (df["J"] + eps))
    w = df["owner_device"].map(WEIGHTS)
    wasi = (trr * w.str[0] + plr * w.str[1] + ndi * w.str[2] + jvi * w.str[3])
    wasi[df["T"].isna()] = np.nan                                # flow absent from baseline
    return wasi


def aggregate_windows(df, secs):
    """Merge consecutive 1-s windows of each flow into `secs`-second windows.
    Traffic metrics are recomputed from packet-weighted sums; detector scores are averaged
    (probabilities / wASI) and then thresholded as usual; a window is 'attack' if the attack
    was active in any of its 1-s windows; a learned detector is scored only if its model had
    completed >= 1 round for every 1-s window in the bin."""
    if secs <= 1:
        return df
    d = df.copy()
    d["bin"] = np.ceil(d["time"] / secs - 1e-9).astype(int)
    d["_dly"] = d["mean_delay_s"] * d["rx_pkts"]
    d["_jit"] = d["mean_jitter_s"] * (d["rx_pkts"] - 1).clip(lower=0)
    agg = {"time": "max", "src": "first", "dst": "first", "owner_device": "first",
           "label_global": "max", "label_targeted": "max", "tx_pkts": "sum", "rx_pkts": "sum",
           "lost_pkts": "sum", "throughput_kbps": "mean", "_dly": "sum", "_jit": "sum"}
    for c, how in [("bflids_round", "min"), ("bflids_prob", "mean"), ("flids_round", "min"),
                   ("flids_lr_prob", "mean"), ("flids_wasi_fixed", "mean")]:
        if c in d.columns:
            agg[c] = how
    keys = ["seed", "file", "flow_id", "bin"]
    g = d.groupby(keys, as_index=False).agg(agg)
    g["mean_delay_s"] = np.where(g.rx_pkts > 0, g._dly / g.rx_pkts.where(g.rx_pkts > 0, 1), 0.0)
    jd = (g.rx_pkts - 1).clip(lower=0)
    g["mean_jitter_s"] = np.where(jd > 0, g._jit / jd.where(jd > 0, 1), 0.0)
    g["loss_pct"] = np.where(g.tx_pkts > 0, 100.0 * g.lost_pkts / g.tx_pkts.where(g.tx_pkts > 0, 1), 0.0)
    return g.drop(columns=["_dly", "_jit", "bin"])


def add_predictions(df, base=None):
    """Scores only the detectors whose columns exist in this framework's logs:
    BFLIDS-only logs -> bflids_cnn; FL-IDS-only logs -> the four FL-IDS pathways."""
    p = pd.DataFrame(index=df.index)
    cols = set(df.columns)
    if BFLIDS_COLS <= cols and df["bflids_round"].notna().any():
        p["bflids_cnn"] = np.where(df["bflids_round"] >= 1, df["bflids_prob"] >= 0.5, np.nan)
    if FLIDS_COLS <= cols and df["flids_round"].notna().any():
        p["flids_classifier"] = np.where(df["flids_round"] >= 1, df["flids_lr_prob"] >= 0.5, np.nan)
        p["wasi_fixed"] = (df["flids_wasi_fixed"] >= 25).astype(float)
        p["flids_fused"] = ((p["wasi_fixed"] == 1) | (p["flids_classifier"] == 1)).astype(float)
        if base is not None:
            w = wasi_perflow(df, base)
            p["wasi_perflow"] = np.where(w.isna(), np.nan, w >= 25)
    return p


def metrics(y, yhat, w=None):
    """Confusion-matrix metrics; with weights w (e.g. packets per window) each window counts
    in proportion to its traffic instead of once."""
    m = ~pd.isna(yhat)
    y, yhat = y[m].astype(bool), yhat[m].astype(bool)
    w = pd.Series(1.0, index=y.index) if w is None else w[m].astype(float)
    tp = float(w[y & yhat].sum()); fp = float(w[~y & yhat].sum())
    tn = float(w[~y & ~yhat].sum()); fn = float(w[y & ~yhat].sum())
    n = tp + fp + tn + fn
    prec = tp / (tp + fp) if tp + fp else np.nan
    rec = tp / (tp + fn) if tp + fn else np.nan
    f1 = 2 * prec * rec / (prec + rec) if prec and rec and not np.isnan(prec + rec) else np.nan
    fpr = fp / (fp + tn) if fp + tn else np.nan
    acc = (tp + tn) / n if n else np.nan
    return dict(n=n, TP=tp, FP=fp, TN=tn, FN=fn, precision=prec, recall=rec, F1=f1, FPR=fpr, accuracy=acc)


def evaluate(df, label_col, base, tag, window=1, weight="windows"):
    # Predictions are computed PER LOG FILE, so each framework's log is scored only by the
    # detectors that framework actually ran (FL-IDS pathways on FL-IDS logs, BFLIDS on BFLIDS logs).
    rows = []
    for (seed, f), g in df.groupby(["seed", "file"]):
        g = aggregate_windows(g.dropna(axis=1, how="all"), window)
        preds = add_predictions(g, base)
        w = (g["tx_pkts"] + g["rx_pkts"]).clip(lower=1) if weight == "packets" else None
        for det in preds.columns:
            if preds[det].isna().all():
                continue
            r = metrics(g[label_col], preds[det], w)
            r.update(set=tag, seed=seed, file=f, detector=det)
            rows.append(r)
    return pd.DataFrame(rows)


def summarise(res):
    cols = ["precision", "recall", "F1", "FPR", "accuracy"]
    agg = res.groupby(["set", "detector"])[cols].agg(["mean", "std"])
    agg.columns = [f"{a}_{b}" for a, b in agg.columns]
    pooled = []
    for (s, d), g in res.groupby(["set", "detector"]):
        tp, fp, tn, fn = g.TP.sum(), g.FP.sum(), g.TN.sum(), g.FN.sum()
        pooled.append(dict(set=s, detector=d, windows=round(float(g.n.sum())), seeds=g.seed.nunique(),
                           pooled_precision=tp / (tp + fp) if tp + fp else np.nan,
                           pooled_recall=tp / (tp + fn) if tp + fn else np.nan,
                           pooled_FPR=fp / (fp + tn) if fp + tn else np.nan))
    return agg.reset_index().merge(pd.DataFrame(pooled), on=["set", "detector"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--benign", nargs="*", default=[])
    ap.add_argument("--baseline", nargs="*", default=[])
    ap.add_argument("--label", choices=["targeted", "global"], default="targeted")
    ap.add_argument("--out", default="comparison_results")
    ap.add_argument("--window", type=int, default=1,
                    help="evaluation window length in seconds (1 = raw 1-s windows; e.g. 10)")
    ap.add_argument("--weight", choices=["windows", "packets"], default="windows",
                    help="count each window once, or in proportion to its packets")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    base = per_flow_baseline(load(a.baseline, "--baseline"), a.window) if a.baseline else None
    label_col = f"label_{a.label}"
    parts = [evaluate(load(a.runs), label_col, base, "attack", a.window, a.weight)]
    if a.benign:
        parts.append(evaluate(load(a.benign, "--benign"), label_col, base, "benign", a.window, a.weight))
    res = pd.concat(parts, ignore_index=True)
    summ = summarise(res)
    res.to_csv(os.path.join(a.out, "per_seed_metrics.csv"), index=False)
    summ.to_csv(os.path.join(a.out, "summary.csv"), index=False)

    pd.set_option("display.width", 200, "display.max_columns", 30)
    print(f"\nLabel: {label_col} | window: {a.window}s | weighting: {a.weight} "
          f"| baseline for wasi_perflow: {'yes' if base is not None else 'not given'}\n")
    show = ["set", "detector", "seeds", "windows", "precision_mean", "recall_mean", "F1_mean", "FPR_mean"]
    print(summ[show].round(3).to_string(index=False))

    # LaTeX rows for the manuscript table (attack set metrics + benign FPR)
    names = {"wasi_fixed": "wASI threshold (on-board, fixed ref.)",
             "wasi_perflow": "wASI threshold (per-flow baseline)",
             "flids_classifier": "FL-IDS FedAvg classifier (proposed)",
             "flids_fused": "FL-IDS fused rule (proposed)",
             "bflids_cnn": "BFLIDS CNN~\\cite{begum2024} (re-impl.)"}
    att = summ[summ.set == "attack"].set_index("detector")
    ben = summ[summ.set == "benign"].set_index("detector") if a.benign else None
    f = lambda m, s: "--" if pd.isna(m) else (f"{m:.3f}" if pd.isna(s) else f"{m:.3f}$\\pm${s:.3f}")
    lines = []
    for d, nm in names.items():
        if d not in att.index:
            continue
        r = att.loc[d]
        fpr = ben.loc[d] if ben is not None and d in ben.index else None
        lines.append(f"{nm} & {f(r.precision_mean, r.precision_std)} & {f(r.recall_mean, r.recall_std)} & "
                     f"{f(r.F1_mean, r.F1_std)} & "
                     f"{f(fpr.FPR_mean, fpr.FPR_std) if fpr is not None else '--'} \\\\")
    with open(os.path.join(a.out, "latex_rows.tex"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\nLaTeX rows written to", os.path.join(a.out, "latex_rows.tex"))


if __name__ == "__main__":
    main()
