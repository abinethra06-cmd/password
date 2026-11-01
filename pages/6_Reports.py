import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

import ui_helpers as ui
from backend import database as db, reporting

st.set_page_config(page_title="Reports", page_icon=":material/download:",
                   layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/download: Security Audit Reports")

runs = db.list_runs()
if not runs:
    st.info("No audits to report on yet. Run one from the **Run Audit** page.")
    st.stop()

labels = {f'Run #{r["id"]} - {r["dataset_name"]} - {r["attack_type"]} '
          f'({r["cracked_count"]}/{r["total_hashes"]} recovered)': r["id"]
          for r in runs}
default_idx = 0
if st.session_state.get("last_run_id") in labels.values():
    ids = list(labels.values())
    default_idx = ids.index(st.session_state["last_run_id"])

label = st.selectbox("Audit run", list(labels.keys()), index=default_idx)
run_id = labels[label]

reveal = st.toggle(
    "Reveal recovered (synthetic) passwords in the PDF", value=False,
    help="Off by default. Recovered values are synthetic test passwords.")

if st.button(":material/build: Generate reports", type="primary"):
    with st.spinner("Generating PDF, CSV and JSON..."):
        pdf_path = reporting.generate_pdf(run_id, reveal=reveal)
        csv_path = reporting.export_csv(run_id)
        json_path = reporting.export_json(run_id)
    st.session_state["report_paths"] = {
        "pdf": pdf_path, "csv": csv_path, "json": json_path}
    st.success("Reports generated.")

paths = st.session_state.get("report_paths")
if paths and all(os.path.exists(p) for p in paths.values()):
    c1, c2, c3 = st.columns(3)
    with c1:
        with open(paths["pdf"], "rb") as fh:
            st.download_button("Download PDF", fh.read(),
                               file_name=os.path.basename(paths["pdf"]),
                               mime="application/pdf", width="stretch")
    with c2:
        with open(paths["csv"], "rb") as fh:
            st.download_button("Download CSV", fh.read(),
                               file_name=os.path.basename(paths["csv"]),
                               mime="text/csv", width="stretch")
    with c3:
        with open(paths["json"], "rb") as fh:
            st.download_button("Download JSON", fh.read(),
                               file_name=os.path.basename(paths["json"]),
                               mime="application/json", width="stretch")
    st.caption(f"Saved locally under: {os.path.dirname(paths['pdf'])}")

ui.sidebar_notice()
