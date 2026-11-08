"""Build the anonymized, balanced Java dataset from the NIST SARD Juliet Java 1.3 suite.

Selection protocol (fixed BEFORE any model was queried):
  1. Eligible test cases: Juliet Java 1.3, flow variant 01 (baseline, no control-flow
     obfuscation), data source `getParameter_Servlet` (HTTP request parameter, an
     unambiguous externally controlled input). One CWE = one eligible family.
  1b. Exclude families whose Safe variant still dereferences a possibly-null request
     parameter (see main()); their labels would contradict the CWE-690 family.
  2. Draw 10 distinct CWEs from the eligible pool with random.Random(SEED).
     If a CWE has several eligible files (different sinks), draw one with the same RNG.
  3. From each selected file take two methods:
       bad()      -> label Vulnerable (Juliet: contains the flaw)
       goodB2G()  -> label Safe (bad source, fixed sink)  if present, else
       goodG2B()  -> label Safe (fixed source, same sink)
  4. Anonymize: strip all comments, rename the method to `handleRequest`, make it
     public, drop the Juliet support import, wrap it in a neutral servlet class,
     and keep the original imports so APIs remain resolvable. Then (4b) rewrite
     the string literals that carry label cues (see LITERAL_REWRITES).
  5. Shuffle the 20 snippets with the same RNG and assign IDs S01..S20.

Usage: python -I build_dataset.py <juliet_testcases_dir> <out_dir>
"""
import csv
import hashlib
import json
import random
import re
import sys
from pathlib import Path

SEED = 20261021
N_CWES = 10
SOURCE_TAG = "getParameter_Servlet"
JULIET_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip"
JULIET_SHA256 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
LEAK_PATTERN = re.compile(r"\b(bad|good|flaw|fix|cwe|juliet|testcase|vulnerab|sink|source)\w*", re.I)


def strip_comments(code: str) -> str:
    """Remove // and /* */ comments while respecting string and char literals."""
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c in "\"'":
            j = i + 1
            while j < n and code[j] != c:
                j += 2 if code[j] == "\\" else 1
            out.append(code[i:j + 1])
            i = j + 1
        elif code.startswith("//", i):
            while i < n and code[i] != "\n":
                i += 1
        elif code.startswith("/*", i):
            end = code.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def extract_method(code: str, name: str) -> str:
    m = re.search(r"^[ \t]*(public|private)\s+void\s+" + name + r"\s*\(", code, re.M)
    if not m:
        raise ValueError(f"method {name} not found")
    start = m.start()
    brace = code.index("{", m.end())
    depth, i = 0, brace
    while True:
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i + 1]
        i += 1


def normalize(method: str, original_name: str) -> str:
    method = re.sub(r"^(\s*)(public|private)\s+void\s+" + original_name + r"\s*\(",
                    r"\1public void handleRequest(", method, count=1)
    lines = [ln.rstrip() for ln in method.splitlines()]
    out, blank = [], False
    for ln in lines:  # collapse runs of blank lines left by removed comments
        if not ln.strip():
            if not blank:
                out.append("")
            blank = True
        else:
            out.append(ln)
            blank = False
    # dedent to class-member indentation (4 spaces)
    indent = min(len(l) - len(l.lstrip()) for l in out if l.strip())
    return "\n".join(("    " + l[indent:]) if l.strip() else "" for l in out)


# Step 4b: neutralize label cues that Juliet places inside string literals. These rewrites
# change only literal text (no data flow, no API, no control logic), identically for the
# vulnerable and the safe variant of a pair.
LITERAL_REWRITES = [
    (re.compile(r"\bbad\(\)"), "result"),                                  # "<br>bad() - ..." print prefixes
    (re.compile(r'getParameter\("CWE\d+"\)'), 'getParameter("name")'),     # parameter named after the CWE
    (re.compile(r'"[^"\n]*CWE643_Xpath_Injection__Helper\.xml"'), lambda m:  # helper XML path
        '"\\\\data\\\\users.xml"' if "\\\\" in m.group(0) else '"./data/users.xml"'),
]


def neutralize(code: str) -> str:
    for pat, rep in LITERAL_REWRITES:
        code = pat.sub(rep, code)
    return code


def header_field(code: str, key: str) -> str:
    m = re.search(r"\*\s*" + re.escape(key) + r"\s*:\s*(.+)", code)
    return m.group(1).strip() if m else ""


def main(src_dir: str, out_dir: str) -> None:
    src, out = Path(src_dir), Path(out_dir)
    (out / "snippets").mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in src.rglob(f"*{SOURCE_TAG}*_01.java"))
    pool: dict[str, list[Path]] = {}
    for p in files:
        pool.setdefault(p.name.split("__")[0], []).append(p)
    # Eligibility rule 1b (added after ground-truth review of a first draw, before any model
    # was queried): exclude families whose code calls stringNumber.trim() on the unchecked
    # getParameter() result. Their Safe variants still contain an unchecked NULL dereference,
    # i.e. the CWE-690 weakness that the CWE-690 family labels Vulnerable, so their
    # ground truth would be internally inconsistent.
    excluded = sorted(c for c, ps in pool.items()
                      if any("stringNumber.trim()" in p.read_text(encoding="utf-8", errors="replace") for p in ps))
    for c in excluded:
        del pool[c]
    print("excluded (inconsistent ground truth):", excluded)
    rng = random.Random(SEED)
    cwes = sorted(rng.sample(sorted(pool), N_CWES), key=lambda c: int(re.match(r"CWE(\d+)", c).group(1)))

    rows = []
    for cwe in cwes:
        path = rng.choice(sorted(pool[cwe]))
        code = path.read_text(encoding="utf-8", errors="replace")
        safe_name = "goodB2G" if re.search(r"void goodB2G\s*\(", code) else "goodG2B"
        imports = [ln for ln in code.splitlines()
                   if ln.startswith("import ") and "testcasesupport" not in ln]
        rel = path.relative_to(src.parent.parent).as_posix()  # src/testcases/...
        for method, label in (("bad", "Vulnerable"), (safe_name, "Safe")):
            body = neutralize(normalize(strip_comments(extract_method(code, method)), method))
            snippet = "\n".join(imports) + "\n\npublic class RequestHandler extends HttpServlet\n{\n" + body + "\n}\n"
            leaks = sorted(set(m.group(0) for m in LEAK_PATTERN.finditer(snippet)))
            if method == "bad":
                reason = (f"Juliet bad(): externally controlled request parameter reaches the sink without "
                          f"the required control. BadSink: {header_field(code, 'BadSink')}")
            elif method == "goodB2G":
                reason = (f"Juliet goodB2G(): same untrusted source, sink protected. "
                          f"GoodSink: {header_field(code, 'GoodSink')}")
            else:
                reason = (f"Juliet goodG2B(): data comes from a trusted source "
                          f"({header_field(code, 'GoodSource')}); same sink as bad().")
            rows.append(dict(cwe=cwe, juliet_file=rel, juliet_method=method, label=label,
                             flow_variant="01", reason=reason, code=snippet,
                             leak_tokens=";".join(leaks), loc=snippet.count("\n") + 1))

    rng.shuffle(rows)
    for i, r in enumerate(rows, 1):
        r["sample_id"] = f"S{i:02d}"
        r["code_sha256"] = hashlib.sha256(r["code"].encode()).hexdigest()[:16]
        (out / "snippets" / f"{r['sample_id']}.java").write_text(r["code"], encoding="utf-8")

    meta_cols = ["sample_id", "label", "cwe", "juliet_file", "juliet_method", "flow_variant",
                 "reason", "loc", "code_sha256", "leak_tokens"]
    with open(out / "dataset.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=meta_cols + ["source_url", "dataset_version", "language", "code"])
        w.writeheader()
        for r in rows:
            w.writerow({**{k: r[k] for k in meta_cols}, "source_url": JULIET_URL,
                        "dataset_version": f"Juliet Test Suite for Java v1.3 (2017-10-01), zip sha256={JULIET_SHA256}",
                        "language": "Java", "code": r["code"]})
    # model-facing file: no labels, no provenance
    with open(out / "model_inputs.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({"sample_id": r["sample_id"], "code": r["code"]}) + "\n")
    print("eligible CWEs:", len(pool), sorted(pool))
    print("selected CWEs:", cwes)
    for r in rows:
        print(r["sample_id"], r["label"], r["cwe"], r["juliet_method"], r["loc"], "leaks:", r["leak_tokens"] or "-")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
