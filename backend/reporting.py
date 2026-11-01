"""Audit report generation: PDF (fpdf2), CSV, and JSON.

Reconstructs a run's summary from persisted data and renders a shareable
report. Recovered passwords are SYNTHETIC; they are REDACTED by default in the
PDF and can be revealed with `reveal=True` for classroom demonstration.
"""
from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from typing import Optional

import config
from backend import database as db
from backend import risk

from fpdf import FPDF


def _latin1(text: str) -> str:
    """Core PDF fonts are latin-1; drop anything outside it safely."""
    return (text or "").encode("latin-1", "replace").decode("latin-1")


def _load(run_id: int, db_path: Optional[str] = None):
    run = db.get_run(run_id, db_path=db_path)
    if not run:
        raise ValueError(f"No run with id {run_id}")
    results = db.get_results(run_id, db_path=db_path)
    entries = db.get_entries(run["dataset_id"], db_path=db_path)
    summary = risk.summarize(results, entries=entries)
    summary["recommendations"] = risk.recommendations(summary)
    return run, results, summary


# --- CSV / JSON ------------------------------------------------------------
def export_csv(run_id: int, out_path: Optional[str] = None,
               db_path: Optional[str] = None) -> str:
    run, results, _ = _load(run_id, db_path)
    out_path = out_path or os.path.join(config.REPORT_DIR, f"audit_run_{run_id}.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["username", "hash_algo", "cracked", "method", "risk_level",
                    "attempts", "time_sec", "recovered_password"])
        for r in results:
            w.writerow([r["username"], r["hash_algo"], bool(r["cracked"]),
                        r["method"] or "", r["risk_level"] or "", r["attempts"],
                        r["time_sec"], r["recovered_password"] or ""])
    return out_path


def export_json(run_id: int, out_path: Optional[str] = None,
                db_path: Optional[str] = None) -> str:
    run, results, summary = _load(run_id, db_path)
    out_path = out_path or os.path.join(config.REPORT_DIR, f"audit_run_{run_id}.json")
    payload = {"run": run, "summary": summary, "results": results,
               "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return out_path


# --- PDF -------------------------------------------------------------------
class _Report(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120)
        self.cell(0, 6, _latin1(config.APP_TITLE), align="R",
                  new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(120)
        self.cell(0, 6, f"Authorized testing only - synthetic data - page {self.page_no()}",
                  align="C")
        self.set_text_color(0)


def _section(pdf: _Report, title: str):
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(235, 238, 245)
    pdf.cell(0, 8, _latin1(title), new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 10)


def generate_pdf(run_id: int, out_path: Optional[str] = None, reveal: bool = False,
                 db_path: Optional[str] = None) -> str:
    run, results, summary = _load(run_id, db_path)
    out_path = out_path or os.path.join(config.REPORT_DIR, f"audit_run_{run_id}.pdf")

    pdf = _Report()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "Security Audit Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90)
    pdf.cell(0, 6, _latin1(config.APP_TAGLINE), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0)

    # Disclaimer
    pdf.ln(2)
    pdf.set_draw_color(180)
    pdf.set_fill_color(252, 246, 230)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, _latin1(
        "AUTHORIZED USE ONLY. This report was produced by an authorized password "
        "security assessment against SYNTHETIC test data. It must not be used to "
        "access accounts without explicit permission. No real user secrets are "
        "collected or stored."), border=1, fill=True)

    # Run metadata
    _section(pdf, "Audit Overview")
    meta = [
        ("Dataset", run.get("dataset_name", "")),
        ("Attack type", run.get("attack_type", "")),
        ("Started", run.get("started_at", "")),
        ("Finished", run.get("finished_at", "")),
        ("Duration (s)", f"{run.get('duration_sec', 0):.3f}"),
        ("Accounts audited", str(summary["total_accounts"])),
        ("Algorithms", ", ".join(summary["algorithms"]) or "n/a"),
    ]
    for k, v in meta:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(45, 6, _latin1(k))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, _latin1(str(v)), new_x="LMARGIN", new_y="NEXT")

    # Summary
    _section(pdf, "Results Summary")
    pdf.multi_cell(0, 6, _latin1(
        f"Passwords recovered: {summary['cracked_count']} / "
        f"{summary['total_accounts']}  ({summary['crack_rate_pct']}%)\n"
        f"Overall risk: {summary['overall_risk']}        "
        f"Storage grade: {summary['storage_grade']}\n"
        f"Total candidate attempts: {run.get('total_hashes','')}"),
        new_x="LMARGIN", new_y="NEXT")
    rc = summary["risk_counts"]
    pdf.multi_cell(0, 6, _latin1(
        f"Risk breakdown -  Critical: {rc.get('Critical',0)}   "
        f"High: {rc.get('High',0)}   Medium: {rc.get('Medium',0)}   "
        f"Low: {rc.get('Low',0)}"), new_x="LMARGIN", new_y="NEXT")

    # Storage notes
    if summary["storage_notes"]:
        _section(pdf, "Password Storage Assessment")
        for n in summary["storage_notes"]:
            pdf.multi_cell(0, 5, _latin1("- " + n), new_x="LMARGIN", new_y="NEXT")

    # Account table
    _section(pdf, "Per-Account Findings")
    headers = [("Username", 32), ("Algo", 24), ("Cracked", 18),
               ("Method", 24), ("Risk", 20), ("Recovered", 62)]
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230)
    for title, w in headers:
        pdf.cell(w, 7, title, border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    for r in results:
        recovered = "-"
        if r["cracked"]:
            recovered = r["recovered_password"] if reveal else "[redacted]"
        row = [r["username"], r["hash_algo"], "Yes" if r["cracked"] else "No",
               r["method"] or "-", r["risk_level"] or "-", recovered]
        for (title, w), val in zip(headers, row):
            pdf.cell(w, 6, _latin1(str(val)[: int(w / 2)]), border=1)
        pdf.ln()

    # Recommendations
    _section(pdf, "Recommendations")
    for rec in summary["recommendations"]:
        pdf.multi_cell(0, 5, _latin1("- " + rec), new_x="LMARGIN", new_y="NEXT")

    # Limitations
    _section(pdf, "Method Limitations")
    pdf.multi_cell(0, 5, _latin1(
        "- Dictionary: only finds passwords present in the wordlist.\n"
        "- Hybrid: only rule-expressible mutations; candidate space grows fast.\n"
        "- Rainbow/lookup: storage grows with coverage and is defeated by salting; "
        "this tool uses a direct hash-lookup table, not reduction-chain rainbow tables.\n"
        "- Results are bounded by the chosen wordlist and single-machine Python "
        "speed; a dedicated GPU cracker would be faster."),
        new_x="LMARGIN", new_y="NEXT")

    pdf.output(out_path)
    return out_path
