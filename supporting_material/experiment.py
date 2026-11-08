"""Run the prompting experiment and store every raw response before any analysis.

Backends
  ollama     local model through the Ollama HTTP API (primary experiment, Qwen3.5:9B)
  anthropic  Claude through the Messages API (needs a valid ANTHROPIC_API_KEY; not usable
             on 2026-10-21 because the available key was rejected, see limitations.md)
  export     write the exact wrapped prompts for isolated Claude subagents (agent_prompts.jsonl)

Examples
  python -I experiment.py ollama --run-id qwen_primary --limit 0
  python -I experiment.py ollama --run-id qwen_pilot --samples S01 S02
  python -I experiment.py export
  python -I experiment.py anthropic --run-id claude_api --model claude-sonnet-5-5

Each call is appended to results/raw/<run_id>.jsonl immediately, so an interrupted run
keeps everything collected so far. Responses are never edited.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import random
import re
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONDITIONS = ("basic", "structured")
OLLAMA_URL = "http://localhost:11434"
OLLAMA_OPTIONS = {"temperature": 0, "seed": 42, "num_ctx": 8192, "num_predict": 2048}


def load_prompts() -> dict[str, str]:
    """Read the frozen templates from prompts.txt (single source of truth)."""
    text = (HERE / "prompts.txt").read_text(encoding="utf-8")
    rule = r"\n-{20,}\n"
    parts = re.split(rule + r"\[([A-Z -]+)\][^\n]*" + rule, text)
    sections = {parts[i]: parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}
    return {"basic": sections["BASIC"], "structured": sections["STRUCTURED"],
            "agent_wrapper": sections["CLAUDE-AGENT WRAPPER"].split("\n\n<the")[0].strip()}


def load_inputs() -> list[dict]:
    with open(HERE / "data" / "model_inputs.jsonl", encoding="utf-8") as f:
        return [json.loads(l) for l in f]


def build_prompt(templates: dict, condition: str, code: str) -> str:
    return templates[condition].replace("{code}", code.rstrip("\n"))


def http_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 600) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"content-type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def call_ollama(model: str, prompt: str, think: bool) -> dict:
    payload = {"model": model, "stream": False, "think": think, "options": OLLAMA_OPTIONS,
               "messages": [{"role": "user", "content": prompt}]}
    t0 = time.time()
    d = http_json(f"{OLLAMA_URL}/api/chat", payload)
    return {"response": d["message"]["content"], "thinking": d["message"].get("thinking", ""),
            "done_reason": d.get("done_reason"), "prompt_tokens": d.get("prompt_eval_count"),
            "output_tokens": d.get("eval_count"), "wall_seconds": round(time.time() - t0, 2),
            "model_reported": d.get("model")}


def call_anthropic(model: str, prompt: str) -> dict:
    payload = {"model": model, "max_tokens": 2048, "temperature": 0,
               "messages": [{"role": "user", "content": prompt}]}
    headers = {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"}
    t0 = time.time()
    d = http_json("https://api.anthropic.com/v1/messages", payload, headers)
    text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
    return {"response": text, "thinking": "", "done_reason": d.get("stop_reason"),
            "prompt_tokens": d["usage"]["input_tokens"], "output_tokens": d["usage"]["output_tokens"],
            "wall_seconds": round(time.time() - t0, 2), "model_reported": d.get("model")}


def ollama_model_info(model: str) -> dict:
    d = http_json(f"{OLLAMA_URL}/api/show", {"model": model})
    tags = json.loads(urllib.request.urlopen(f"{OLLAMA_URL}/api/tags").read())
    digest = next((m["digest"] for m in tags["models"] if m["name"] == model), None)
    ver = json.loads(urllib.request.urlopen(f"{OLLAMA_URL}/api/version").read())["version"]
    return {"digest": digest, "details": d.get("details"), "ollama_version": ver,
            "model_default_parameters": d.get("parameters")}


def run(args) -> None:
    templates, inputs = load_prompts(), load_inputs()
    if args.samples:
        inputs = [x for x in inputs if x["sample_id"] in args.samples]
    jobs = [(x, c) for x in inputs for c in CONDITIONS]
    random.Random(args.order_seed).shuffle(jobs)  # interleave conditions; no shared state between calls
    out = HERE / "results" / "raw" / f"{args.run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():  # resume support: skip pairs already recorded
        done = {(r["sample_id"], r["condition"]) for r in map(json.loads, out.read_text(encoding="utf-8").splitlines())}
    meta = {"run_id": args.run_id, "backend": args.backend, "model": args.model,
            "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "host": platform.platform(),
            "python": platform.python_version(), "think": args.think}
    if args.backend == "ollama":
        meta.update(ollama_model_info(args.model), options=OLLAMA_OPTIONS)
    else:
        meta.update(options={"temperature": 0, "max_tokens": 2048})
    (out.parent / f"{args.run_id}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))

    with open(out, "a", encoding="utf-8") as f:
        for i, (x, cond) in enumerate(jobs, 1):
            if (x["sample_id"], cond) in done:
                continue
            prompt = build_prompt(templates, cond, x["code"])
            ts = dt.datetime.now(dt.timezone.utc).isoformat()
            try:
                res = call_ollama(args.model, prompt, args.think) if args.backend == "ollama" \
                    else call_anthropic(args.model, prompt)
                err = ""
            except Exception as e:  # keep failures visible in the raw log
                res, err = {"response": ""}, f"{type(e).__name__}: {e}"
            rec = {"run_id": args.run_id, "model": args.model, "condition": cond, "sample_id": x["sample_id"],
                   "timestamp_utc": ts, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()[:16],
                   "error": err, **res}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            print(f"[{i}/{len(jobs)}] {x['sample_id']} {cond:10s} tokens={res.get('output_tokens')} "
                  f"t={res.get('wall_seconds')}s err={err or '-'} :: {res['response'][-60:]!r}")


def export(args) -> None:
    """Write the exact wrapped prompts given to the isolated Claude subagents."""
    templates, inputs = load_prompts(), load_inputs()
    out = HERE / "results" / "agent_prompts.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for x in inputs:
            for cond in CONDITIONS:
                p = templates["agent_wrapper"] + "\n\n" + build_prompt(templates, cond, x["code"])
                f.write(json.dumps({"sample_id": x["sample_id"], "condition": cond, "prompt": p,
                                    "prompt_sha256": hashlib.sha256(p.encode()).hexdigest()[:16]}) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("backend", choices=["ollama", "anthropic", "export"])
    ap.add_argument("--run-id", default="run")
    ap.add_argument("--model", default="qwen3.5:9b")
    ap.add_argument("--think", type=lambda s: s.lower() == "true", default=False)
    ap.add_argument("--samples", nargs="*")
    ap.add_argument("--order-seed", type=int, default=7)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    export(a) if a.backend == "export" else run(a)
