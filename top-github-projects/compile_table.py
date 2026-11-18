"""M063 compiler: turn the private report exports into the public table.

Reads only each CSV's ``assessment`` rows (the overall grade and one row per
rubric category) and its ``context`` rubric name, plus the job's evidence log.
Writes ``index.html`` and ``data.json`` with grades and finding counts only
(D7): nothing finding-level, no paths, rule names or secret values. Rows the
owner holds for private notification (D8) show no grades. Usage:

    python scripts/m063/compile_table.py --evidence m063-out/evidence.jsonl \\
        --csv-dir m063-out/csv --out m063-site [--hold 12,40]
"""

from __future__ import annotations

import argparse
import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = ROOT / "docs" / "M063" / "projects.csv"
CATEGORIES = (("secrets", "Secrets"), ("sast", "SAST"), ("iac", "Infrastructure"),
              ("dependency", "Dependency health"), ("license", "License exposure"),
              ("remediation", "Remediation"))
# Refusals from our own tooling are summarised; product refusals keep their reason.
TOOL_STEPS = {"clone": "the default branch could not be cloned",
              "scan": "the scan did not complete"}
# A project our own run could not scan or upload is shown as failed (D21), so
# those rows stand apart from projects a stock product limit stops (D5).
FAILED_STEPS = frozenset({"clone", "scan", "ingest"})


def _cell(value: str | None) -> str:
    """Undo the export's spreadsheet-safety prefix for display."""
    value = value or ""
    return value[1:] if value.startswith("'") else value


def read_assessment(path: Path) -> dict:
    overall, categories, rubric = {}, {}, ""
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            kind = row.get("record_type")
            if kind == "context" and row.get("rubric"):
                rubric = _cell(row["rubric"])
            if kind != "assessment":
                continue
            entry = {"grade": _cell(row.get("grade")) or None,
                     "score": _cell(row.get("score")) or None,
                     "count": int(row["count"]) if (row.get("count") or "").isdigit() else None}
            if row.get("category") == "overall":
                overall = {**entry, "provisional": _cell(row.get("status")) == "provisional"}
            elif row.get("category") in dict(CATEGORIES):
                categories[row["category"]] = entry
    return {"overall": overall, "categories": categories, "rubric": rubric}


def report_diagnostics(path: Path) -> dict:
    """Why a report is or is not graded, from the report's own product messages.

    Reads only ``source_warning``, ``cap`` and ``context`` reasons (fixed product
    text), whether each ``source`` row names a run and snapshot, and how many
    ``finding`` rows exist. Finding contents are never read into the output.
    """
    reasons, sources, findings = [], [], 0
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            kind = row.get("record_type")
            if kind == "finding":
                findings += 1
            elif kind == "source":
                sources.append({"repo_key": _cell(row.get("repo_key")) or None,
                                "ref": _cell(row.get("ref")) or None,
                                "has_run": bool(_cell(row.get("measured_at"))),
                                "has_snapshot": bool(_cell(row.get("snapshot_ref")))})
            elif kind in ("source_warning", "cap", "context") and _cell(row.get("reason")):
                reason = _cell(row["reason"])[:300]
                if reason not in reasons:
                    reasons.append(reason)
    return {"finding_rows": findings, "sources": sources, "reasons": reasons[:20]}


# A failed scan names the scanner component and its diagnostic code (D21).
# Both are allowlisted again here, so nothing else reaches the public page.
SCAN_COMPONENTS = frozenset({"gitleaks", "semgrep", "kics", "grype", "php-vuln"})
SCAN_CODES = {"timeout": "ran past its time limit",
              "execution_failed": "stopped before finishing"}
SCAN_OTHER_CODES = frozenset({"not_installed", "output_missing", "invalid_output", "scope_unresolved"})


def _scan_reason(component: object) -> str:
    name, _, code = str(component or "").partition(":")
    if name in SCAN_COMPONENTS and code in SCAN_CODES:
        return f"the {name} scanner {SCAN_CODES[code]}"
    if name in SCAN_COMPONENTS and code in SCAN_OTHER_CODES:
        return f"the {name} scanner did not complete ({code.replace('_', ' ')})"
    return TOOL_STEPS["scan"]


def _reason(refusal: dict) -> str:
    step = refusal.get("step", "")
    if step == "scan":
        return _scan_reason(refusal.get("component"))
    if step in TOOL_STEPS:
        return TOOL_STEPS[step]
    detail = refusal.get("detail")
    if isinstance(detail, dict):
        detail = detail.get("detail", detail)
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("code")
    return str(detail or f"{step} refused")[:200]


def compile_rows(projects: Path, evidence: Path, csv_dir: Path, hold: set[int]) -> list[dict]:
    with projects.open(newline="", encoding="utf-8") as handle:
        frozen = list(csv.DictReader(handle))
    latest = {}
    if evidence.is_file():
        for line in evidence.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                latest[int(record["rank"])] = record
    rows = []
    for project in frozen:
        rank = int(project["rank"])
        record = latest.get(rank, {})
        row = {"rank": rank, "repository": project["full_name"],
               "url": f"https://github.com/{project['full_name']}",
               "stars": int(project["stars"]), "status": "pending"}
        if rank in hold:
            row["status"] = "held"
        elif record.get("csv"):
            assessment = read_assessment(csv_dir / record["csv"])
            row.update(status="assessed", commit=record.get("commit_sha"),
                       ci_attested=bool(record.get("ci_attested")),
                       component_timeouts=dict(record.get("component_timeouts") or {}),
                       scanned_at=record.get("scanned_at"), rubric=assessment["rubric"],
                       overall=assessment["overall"], categories=assessment["categories"])
        elif record.get("refusal"):
            failed = record["refusal"].get("step") in FAILED_STEPS
            row.update(status="failed" if failed else "not_assessed", reason=_reason(record["refusal"]))
        rows.append(row)
    return rows


def _status_text(row: dict) -> str:
    """The text a row without grades shows in place of them."""
    if row["status"] == "failed":
        return f"Failed: {row.get('reason', '')}"
    return {"held": "Under review", "pending": "Not yet scanned"}.get(
        row["status"], f"Not assessed: {row.get('reason', '')}")


def _grade(entry: dict | None) -> str:
    grade = (entry or {}).get("grade")
    return html.escape(grade) if grade else '<span class="muted">Not assessed</span>'


def render_html(rows: list[dict], *, environment: str, scanner: str, snapshot: str,
                generated: str) -> str:
    rubrics = sorted({row["rubric"] for row in rows if row.get("rubric")}) or ["project-security-v2"]
    head = "".join(f'<th scope="col">{html.escape(label)}</th>' for _key, label in CATEGORIES)
    body = []
    for row in rows:
        link = f'<a href="{html.escape(row["url"])}">{html.escape(row["repository"])}</a>'
        cells = [f'<td data-label="Rank">{row["rank"]}</td>', f'<th scope="row" data-label="Project">{link}</th>']
        if row["status"] == "assessed":
            overall = row["overall"]
            label = ' <span class="tag">Provisional</span>' if overall.get("provisional") else ""
            if row.get("ci_attested"):
                label += ' <span class="tag" title="Scanner coverage attested by the CI upload, not observed by SourceBastion">CI-attested</span>'
            if row.get("component_timeouts"):
                budgets = ", ".join(f"{name} {seconds} s" for name, seconds in sorted(row["component_timeouts"].items()))
                label += (' <span class="tag" title="Scanned with a longer time budget than the stock scanner: '
                          f'{html.escape(budgets)}">Longer scan budget</span>')
            cells.append(f'<td data-label="Overall">{_grade(overall)}{label}</td>')
            for key, name in CATEGORIES:
                entry = row["categories"].get(key, {})
                count = entry.get("count")
                count_text = f'<span class="count">{count} findings</span>' if count is not None else ""
                cells.append(f'<td data-label="{html.escape(name)}">{_grade(entry)} {count_text}</td>')
            commit = html.escape((row.get("commit") or "")[:12])
            when = html.escape((row.get("scanned_at") or "")[:10])
            cells.append(f'<td data-label="Scanned">{when}<br><code>{commit}</code></td>')
        else:
            message = _status_text(row)
            cells.append(f'<td data-label="Overall" colspan="{len(CATEGORIES) + 2}">{html.escape(message)}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    assessed = sum(row["status"] == "assessed" for row in rows)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security grades for the 100 most-starred GitHub projects</title>
<style>
:root {{ color-scheme: light dark; --bg:#ffffff; --text:#1b1f23; --muted:#57606a; --line:#d0d7de; --accent:#0b5d3b; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0d1117; --text:#e6edf3; --muted:#9da7b3; --line:#30363d; --accent:#56d364; }} }}
body {{ margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui, sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:24px 16px; }}
a {{ color:var(--accent); }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th, td {{ border-bottom:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }}
thead th {{ position:sticky; top:0; background:var(--bg); }}
.muted, .count {{ color:var(--muted); }}
.count {{ display:block; font-size:12px; }}
.tag {{ font-size:12px; border:1px solid var(--muted); padding:0 4px; border-radius:3px; }}
@media (max-width: 720px) {{
  thead {{ display:none; }}
  table, tbody, tr, th, td {{ display:block; width:auto; }}
  tr {{ border-bottom:2px solid var(--line); padding:8px 0; }}
  th, td {{ border:0; padding:2px 0; }}
  td::before {{ content:attr(data-label) ": "; font-weight:600; }}
}}
</style>
</head>
<body>
<main>
<h1>Security grades for the 100 most-starred GitHub projects</h1>
<p>SourceBastion scanned each project's default branch and graded it with rubric
{html.escape(", ".join(rubrics))}. Each row shows the overall grade and, for every rubric
category, its grade and finding count. {assessed} of {len(rows)} projects are assessed.</p>
<table>
<caption class="muted">Project list frozen at {html.escape(snapshot)} (GitHub search by stars, forks excluded).</caption>
<thead><tr><th scope="col">Rank</th><th scope="col">Project</th><th scope="col">Overall</th>{head}<th scope="col">Scanned</th></tr></thead>
<tbody>
{chr(10).join(body)}
</tbody>
</table>
<h2>Methodology</h2>
<ul>
<li>Rubric: {html.escape(", ".join(rubrics))}. Grades are computed by stock SourceBastion; nothing was adjusted by hand, and no finding was manually reviewed.</li>
<li>Scanner: <code>{html.escape(scanner)}</code>, run on a shallow clone of each default branch and uploaded through SourceBastion's customer-CI API (no webhooks, no access to the projects' repositories).</li>
<li>Most grades are <strong>Provisional</strong>: License exposure is not assessed without an intended-use policy. Remediation is graded by the stock rubric from the project's SourceBastion history.</li>
<li>Stock product limits apply. A project a limit stops is shown as "Not assessed" with the product's reason.</li>
<li>A project this run could not clone, scan or upload is shown as "Failed", naming the scanner that stopped when the scan recorded one. These are mostly very large repositories. Most were retried with a 30-minute limit for each scanner, and some also with one scanner at a time.</li>
<li>Counts are unique actionable findings per category. No finding detail is published.</li>
<li>Source environment: {html.escape(environment)}. Generated {html.escape(generated)}.</li>
</ul>
</main>
</body>
</html>
"""


def render_markdown(rows: list[dict]) -> str:
    """The same grades and counts for the run's job summary, so the owner can review
    the table without any file leaving the runner."""
    head = " | ".join(label for _key, label in CATEGORIES)
    lines = [f"| Rank | Project | Overall | {head} | Commit |",
             "| " + " | ".join(["---"] * (len(CATEGORIES) + 4)) + " |"]
    for row in rows:
        if row["status"] == "assessed":
            overall = row["overall"]
            grade = (overall.get("grade") or "Not assessed") + (" (Provisional)" if overall.get("provisional") else "")
            cells = [f"{(row['categories'].get(key) or {}).get('grade') or 'n/a'}"
                     f" / {(row['categories'].get(key) or {}).get('count', '')}" for key, _label in CATEGORIES]
            commit = (row.get("commit") or "")[:12]
        else:
            grade = _status_text(row)
            cells, commit = [""] * len(CATEGORIES), ""
        name = row["repository"].replace("|", "\\|")
        lines.append(f"| {row['rank']} | {name} | {grade.replace('|', '/')} | " + " | ".join(cells) + f" | {commit} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--csv-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--projects", type=Path, default=PROJECTS)
    parser.add_argument("--hold", default="", help="comma-separated ranks held for private notification (D8)")
    parser.add_argument("--environment", default="dev")
    parser.add_argument("--scanner", default="ghcr.io/sourcebastion/sourcebastion-scanner")
    parser.add_argument("--diagnostics", type=Path,
                        help="also write each assessed report's grading messages here (private review aid)")
    args = parser.parse_args(argv)
    hold = {int(item) for item in args.hold.split(",") if item.strip()}
    rows = compile_rows(args.projects, args.evidence, args.csv_dir, hold)
    with args.projects.open(newline="", encoding="utf-8") as handle:
        snapshot = next(csv.DictReader(handle))["snapshot_utc"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "index.html").write_text(render_html(
        rows, environment=args.environment, scanner=args.scanner, snapshot=snapshot,
        generated=generated), encoding="utf-8")
    public = [{key: value for key, value in row.items() if key != "reason" or row["status"] in ("not_assessed", "failed")}
              for row in rows]
    (args.out / "summary.md").write_text(render_markdown(rows), encoding="utf-8")
    (args.out / "data.json").write_text(json.dumps(
        {"snapshot_utc": snapshot, "environment": args.environment, "generated": generated,
         "rows": public}, indent=1) + "\n", encoding="utf-8")
    if args.diagnostics:
        evidence = {}
        for line in args.evidence.read_text(encoding="utf-8").splitlines():
            record = json.loads(line) if line.strip() else {}
            if record.get("csv"):
                evidence[record["rank"]] = record["csv"]
        diagnostics = {str(rank): report_diagnostics(args.csv_dir / name)
                       for rank, name in sorted(evidence.items()) if rank not in hold}
        args.diagnostics.write_text(json.dumps(diagnostics, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"compiled {sum(r['status'] == 'assessed' for r in rows)} assessed of {len(rows)} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
