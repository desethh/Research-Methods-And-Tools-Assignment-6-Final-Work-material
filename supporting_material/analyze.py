"""Parse raw outputs, score them against ground truth, and produce all derived results.

Inputs : data/dataset.csv, results/raw/<run_id>.jsonl
Outputs: results/raw_outputs.csv, results/predictions.csv, results/metrics.csv,
         results/paired_tests.csv, results/stability.csv, results/disagreements.csv,
         figures/results_comparison.png, figures/confusion_matrices.png

Parsing rule (identical for every condition): take the LAST occurrence of a JSON object
{"label": "Vulnerable"} / {"label": "Safe"} (case-insensitive, whitespace-tolerant) in the
response. If none is found the prediction is UNPARSED; it is kept in predictions.csv and
scored as an error (FN if the truth is Vulnerable, FP if Safe). No response is discarded.
Positive class = Vulnerable.
"""
import csv
import json
import random
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import binomtest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

HERE = Path(__file__).resolve().parent
RES, FIG = HERE / "results", HERE / "figures"
FIG.mkdir(exist_ok=True)
LABEL_RE = re.compile(r'\{\s*"label"\s*:\s*"(vulnerable|safe)"\s*\}', re.I)
RUNS = {  # run_id -> (model label, role)
    "qwen_primary": ("Qwen3.5:9B", "primary"),
    "qwen_rep2": ("Qwen3.5:9B", "repeat"),
    "qwen_rep3": ("Qwen3.5:9B", "repeat"),
    "qwen_think_exploratory": ("Qwen3.5:9B (thinking on)", "exploratory"),
    "claude_agents": ("Claude Sonnet (subagent)", "secondary"),
}
COND = ("basic", "structured")


def parse(text: str) -> str:
    m = LABEL_RE.findall(text or "")
    return m[-1].capitalize() if m else "UNPARSED"


def metrics(y, p) -> dict:
    yb = [int(v == "Vulnerable") for v in y]
    # UNPARSED is always wrong: predict the opposite of the truth
    pb = [int(pp == "Vulnerable") if pp != "UNPARSED" else 1 - t for pp, t in zip(p, yb)]
    tn, fp, fn, tp = confusion_matrix(yb, pb, labels=[0, 1]).ravel()
    return dict(n=len(y), tp=int(tp), tn=int(tn), fp=int(fp), fn=int(fn),
                accuracy=accuracy_score(yb, pb), precision=precision_score(yb, pb, zero_division=0),
                recall=recall_score(yb, pb, zero_division=0), f1=f1_score(yb, pb, zero_division=0),
                unparsed=sum(pp == "UNPARSED" for pp in p))


def fast_f1(rows) -> float:
    """F1 with the same UNPARSED rule as metrics(); used only inside the bootstrap loop."""
    tp = sum(r["truth"] == "Vulnerable" and r["prediction"] == "Vulnerable" for r in rows)
    fp = sum(r["truth"] == "Safe" and r["prediction"] != "Safe" for r in rows)
    fn = sum(r["truth"] == "Vulnerable" and r["prediction"] != "Vulnerable" for r in rows)
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


def main() -> None:
    truth = {r["sample_id"]: r for r in csv.DictReader(open(HERE / "data" / "dataset.csv", encoding="utf-8"))}
    raw, preds = [], []
    for run in RUNS:
        f = RES / "raw" / f"{run}.jsonl"
        if not f.exists():
            print("missing run (not evaluated):", run)
            continue
        for r in map(json.loads, f.read_text(encoding="utf-8").splitlines()):
            raw.append(r)
            t = truth[r["sample_id"]]
            p = parse(r["response"])
            preds.append(dict(run_id=run, model=RUNS[run][0], role=RUNS[run][1], condition=r["condition"],
                              sample_id=r["sample_id"], cwe=t["cwe"], truth=t["label"], prediction=p,
                              correct=int(p == t["label"]), output_tokens=r.get("output_tokens", "")))
    keys = ["run_id", "model", "condition", "sample_id", "timestamp_utc", "prompt_sha256", "error",
            "done_reason", "prompt_tokens", "output_tokens", "wall_seconds", "response", "thinking"]
    with open(RES / "raw_outputs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(sorted(raw, key=lambda r: (r["run_id"], r["sample_id"], r["condition"])))
    preds.sort(key=lambda r: (r["run_id"], r["sample_id"], r["condition"]))
    with open(RES / "predictions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(preds[0]))
        w.writeheader()
        w.writerows(preds)

    def sel(run, cond):
        rows = sorted((p for p in preds if p["run_id"] == run and p["condition"] == cond), key=lambda r: r["sample_id"])
        return rows

    mrows, by = [], {}
    for run in RUNS:
        for cond in COND:
            rows = sel(run, cond)
            if len(rows) != 20:
                continue
            m = metrics([r["truth"] for r in rows], [r["prediction"] for r in rows])
            by[(run, cond)] = (m, rows)
            mout = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in m.items()}
            toks = [int(r["output_tokens"]) for r in rows if str(r["output_tokens"]).isdigit()]
            mrows.append(dict(run_id=run, model=RUNS[run][0], role=RUNS[run][1], condition=cond, **mout,
                              mean_output_tokens=round(sum(toks) / len(toks), 1) if toks else ""))
    with open(RES / "metrics.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(mrows[0]))
        w.writeheader()
        w.writerows(mrows)

    # Paired comparison structured vs basic within each run (same 20 snippets)
    prow = []
    for run in RUNS:
        if (run, "basic") not in by or (run, "structured") not in by:
            continue
        (mb, rb), (ms, rs) = by[(run, "basic")], by[(run, "structured")]
        b = sum(x["correct"] and not y["correct"] for x, y in zip(rb, rs))  # basic right, structured wrong
        c = sum(y["correct"] and not x["correct"] for x, y in zip(rb, rs))  # structured right, basic wrong
        p = binomtest(c, b + c, 0.5).pvalue if b + c else 1.0
        # cluster bootstrap over the 10 CWE pairs for Delta F1
        pairs = sorted({r["cwe"] for r in rb})
        rng, deltas = random.Random(0), []
        for _ in range(10000):
            pick = [rng.choice(pairs) for _ in pairs]
            ib = [r for c_ in pick for r in rb if r["cwe"] == c_]
            is_ = [r for c_ in pick for r in rs if r["cwe"] == c_]
            deltas.append(fast_f1(is_) - fast_f1(ib))
        deltas.sort()
        assert abs(fast_f1(rs) - ms["f1"]) < 1e-9 and abs(fast_f1(rb) - mb["f1"]) < 1e-9  # agrees with sklearn
        prow.append(dict(run_id=run, model=RUNS[run][0], n=len(rb),
                         f1_basic=round(mb["f1"], 4), f1_structured=round(ms["f1"], 4),
                         delta_f1=round(ms["f1"] - mb["f1"], 4),
                         delta_precision=round(ms["precision"] - mb["precision"], 4),
                         delta_recall=round(ms["recall"] - mb["recall"], 4),
                         delta_accuracy=round(ms["accuracy"] - mb["accuracy"], 4),
                         discordant_basic_only_correct=b, discordant_structured_only_correct=c,
                         mcnemar_exact_p=round(p, 4),
                         boot95_delta_f1_low=round(deltas[249], 4), boot95_delta_f1_high=round(deltas[9749], 4)))
    with open(RES / "paired_tests.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(prow[0]))
        w.writeheader()
        w.writerows(prow)

    # Sensitivity analysis (not the primary rule): drop UNPARSED responses instead of scoring them as errors
    sens = []
    for (run, cond), (m, rows) in by.items():
        if m["unparsed"]:
            kept = [r for r in rows if r["prediction"] != "UNPARSED"]
            ms_ = metrics([r["truth"] for r in kept], [r["prediction"] for r in kept])
            sens.append(dict(run_id=run, condition=cond, rule="UNPARSED excluded",
                             **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in ms_.items()}))
    if sens:
        with open(RES / "sensitivity_unparsed.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(sens[0]))
            w.writeheader()
            w.writerows(sens)

    # Stability of Qwen predictions across the three identical runs
    srow = []
    reps = [r for r in ("qwen_primary", "qwen_rep2", "qwen_rep3") if (r, "basic") in by and (r, "structured") in by]
    for cond in COND:
        if len(reps) < 2:
            break
        sets = [[x["prediction"] for x in by[(r, cond)][1]] for r in reps]
        agree = sum(len(set(v)) == 1 for v in zip(*sets))
        srow.append(dict(condition=cond, runs=";".join(reps), samples_identical_across_runs=agree, n=20,
                         f1_per_run=";".join(str(round(by[(r, cond)][0]["f1"], 4)) for r in reps)))
    if srow:
        with open(RES / "stability.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(srow[0]))
            w.writeheader()
            w.writerows(srow)

    # Per-sample view of the four primary conditions
    grid = {}
    for run in ("qwen_primary", "claude_agents"):
        for cond in COND:
            for r in by.get((run, cond), (None, []))[1]:
                grid.setdefault(r["sample_id"], {"sample_id": r["sample_id"], "cwe": r["cwe"], "truth": r["truth"]})[
                    f"{run}_{cond}"] = r["prediction"]
    with open(RES / "per_sample_grid.csv", "w", newline="", encoding="utf-8") as f:
        cols = ["sample_id", "cwe", "truth"] + [f"{a}_{c}" for a in ("qwen_primary", "claude_agents") for c in COND]
        w = csv.DictWriter(f, fieldnames=cols, restval="not evaluated")
        w.writeheader()
        w.writerows(grid[k] for k in sorted(grid))

    plot(by)
    for m in mrows:
        print(m)
    for p in prow:
        print(p)
    for s in srow:
        print(s)


def plot(by) -> None:
    # reference palette (dataviz skill, references/palette.md), light mode, slots 1-4 in fixed order
    series = [("qwen_primary", "basic", "Qwen3.5:9B basic", "#2a78d6", ""),
              ("qwen_primary", "structured", "Qwen3.5:9B structured", "#eb6834", "//"),
              ("claude_agents", "basic", "Claude basic", "#1baf7a", ""),
              ("claude_agents", "structured", "Claude structured", "#eda100", "//")]
    series = [s for s in series if (s[0], s[1]) in by]
    ink, ink2, grid = "#0b0b0b", "#52514e", "#e4e3df"
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": ink2,
                         "axes.labelcolor": ink, "xtick.color": ink2, "ytick.color": ink2})

    names = ["Accuracy", "Precision", "Recall", "F1"]
    keys = ["accuracy", "precision", "recall", "f1"]
    fig, ax = plt.subplots(figsize=(7.0, 2.7), dpi=300)
    w = 0.8 / len(series)
    for i, (run, cond, lab, col, hatch) in enumerate(series):
        m = by[(run, cond)][0]
        xs = [k + (i - (len(series) - 1) / 2) * w for k in range(len(keys))]
        vals = [m[k] for k in keys]
        bars = ax.bar(xs, vals, width=w * 0.92, color=col, edgecolor="white", linewidth=0.6, hatch=hatch, label=lab)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}", ha="center", va="bottom", fontsize=6, color=ink2)
    ax.set_xticks(range(len(keys)), names)
    ax.set_ylim(0, 1.1)
    ax.set_yticks([0, .25, .5, .75, 1])
    ax.set_ylabel("Score (n = 20 snippets)")
    ax.yaxis.grid(True, color=grid, linewidth=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.legend(ncol=len(series), loc="upper center", bbox_to_anchor=(0.5, 1.16), frameon=False, fontsize=7)
    fig.tight_layout()
    fig.savefig(FIG / "results_comparison.png", bbox_inches="tight")
    plt.close(fig)

    fig, axes = plt.subplots(2, 2, figsize=(3.5, 3.4), dpi=300)  # one IEEE column
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("blue", ["#f3f7fd", "#2a78d6", "#0d3a73"])
    for ax, (run, cond, lab, _, _) in zip(axes.flat, series):
        m = by[(run, cond)][0]
        cm = [[m["tp"], m["fn"]], [m["fp"], m["tn"]]]
        ax.imshow(cm, cmap=cmap, vmin=0, vmax=10)
        for i in range(2):
            for j in range(2):
                v = cm[i][j]
                ax.text(j, i, f"{['TP', 'FN'][j] if i == 0 else ['FP', 'TN'][j]}\n{v}", ha="center", va="center",
                        fontsize=7, color="white" if v >= 6 else ink)
        ax.set_xticks([0, 1], ["Pred. Vuln.", "Pred. Safe"], fontsize=6)
        ax.set_yticks([0, 1], ["True Vuln.", "True Safe"], fontsize=6)
        ax.set_title(lab, fontsize=7, color=ink)
        for s in ax.spines.values():
            s.set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "confusion_matrices.png", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
