"""Check that every Juliet manifest flaw line of a selected file lies inside bad(), not inside the
good method used as the Safe sample. Usage: python -I verify_manifest.py <juliet_root> data/dataset.csv"""
import csv, re, sys
from pathlib import Path
root = Path(sys.argv[1])
flaws = {}
# manifest.xml of the official v1.3 zip is not well-formed XML (mismatched tag near line 50084),
# so <file> blocks are parsed with a tolerant regex instead of an XML parser.
text = (root / "manifest.xml").read_text(encoding="utf-8", errors="replace")
for m in re.finditer(r'<file path="([^"]+)"[^>]*>(.*?)</file>', text, re.S):
    flaws[m.group(1).split("/")[-1]] = [(int(l), n) for l, n in re.findall(r'<flaw line="(\d+)" name="([^"]+)"', m.group(2))]
def span(code, name):
    m = re.search(r"^[ \t]*(public|private)\s+void\s+" + name + r"\s*\(", code, re.M)
    i = code.index("{", m.end()); d = 0
    while True:
        d += code[i] == "{"; d -= code[i] == "}"
        if d == 0: break
        i += 1
    return code[:m.start()].count("\n") + 1, code[:i].count("\n") + 1
ok = True
for r in csv.DictReader(open(sys.argv[2], encoding="utf-8")):
    p = root / r["juliet_file"]; code = p.read_text(encoding="utf-8", errors="replace")
    a, b = span(code, r["juliet_method"]); fl = flaws.get(p.name, [])
    inside = [l for l, _ in fl if a <= l <= b]
    good = (len(inside) > 0) if r["label"] == "Vulnerable" else (len(inside) == 0)
    ok &= good
    print(r["sample_id"], r["label"], r["juliet_method"], f"lines {a}-{b}", "manifest flaws:", fl, "->", "OK" if good else "MISMATCH")
print("ALL CONSISTENT" if ok else "INCONSISTENCIES FOUND")
