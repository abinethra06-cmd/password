import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st

import config
import ui_helpers as ui
from backend import audit, database as db

st.set_page_config(page_title="Run Audit", page_icon=":material/play_arrow:",
                   layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/play_arrow: Run a Security Audit")
st.caption("Test a synthetic dataset's password hashes with one or all techniques.")

if not ui.has_data():
    st.info("No datasets found. Generate synthetic data on the Home page first.")
    st.stop()

opts = ui.dataset_options()
col1, col2 = st.columns([2, 1])
with col1:
    label = st.selectbox("Dataset", list(opts.keys()))
    dataset_id = opts[label]
with col2:
    attack = st.selectbox("Technique",
                          ["all", "dictionary", "hybrid", "rainbow"],
                          format_func=lambda a: a.capitalize())

entries = db.get_entries(dataset_id)
salted = all(e["is_salted"] for e in entries)
st.write(f"**{len(entries)}** accounts - "
         f"storage: {'salted (secure)' if salted else 'unsalted (fast hash)'}")
if salted and attack in ("rainbow",):
    st.warning("This dataset is salted: rainbow tables cannot recover salted "
               "hashes. Expect 0 recoveries (that is the point of the demo).")

if salted:
    st.caption("Note: against salted, slow hashes the dictionary/hybrid stages "
               "run under a time budget. This demonstrates that salting makes "
               "batch guessing infeasible; a short run may crack few or none.")

with st.expander("Advanced parameters"):
    max_variants = st.slider("Hybrid: max variants per base word", 50, 1000,
                             config.HYBRID_MAX_VARIANTS_PER_WORD, 50)
    with_variants = st.checkbox("Rainbow: include hybrid variants in the table",
                                value=False)
    salted_budget = st.slider("Salted attack time budget (seconds per stage)",
                              2, 30, 8, 1,
                              help="Caps time spent brute-forcing slow salted "
                                   "hashes so the UI stays responsive.")

if st.button(":material/play_arrow: Run audit", type="primary"):
    bar = st.progress(0.0, text="Starting...")

    def progress(frac, msg):
        bar.progress(min(max(frac, 0.0), 1.0), text=msg)

    params = {"max_variants_per_word": max_variants, "with_variants": with_variants,
              "salted_budget_sec": salted_budget}
    with st.spinner("Running audit..."):
        out = audit.run_audit(dataset_id, attack, params=params, progress=progress)
    bar.progress(1.0, text="Done")
    st.session_state["last_run_id"] = out["run_id"]

    s = out["summary"]
    st.success(f"Audit complete - run #{out['run_id']}")
    if s.get("budget_exhausted"):
        st.warning("The salted attack hit its time budget before finishing - "
                   "some accounts were left untested. Against salted, slow "
                   "hashing, exhaustive guessing is impractical by design.")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Recovered", f"{s['cracked_count']}/{s['total_accounts']}")
    m2.metric("Crack rate", f"{s['crack_rate_pct']}%")
    m3.metric("Overall risk", s["overall_risk"])
    m4.metric("Storage grade", s["storage_grade"])

    for note in s["storage_notes"]:
        st.info(note)

    df = pd.DataFrame(out["results"])[
        ["username", "hash_algo", "cracked", "method", "risk_level",
         "attempts", "recovered_password"]].copy()
    reveal = st.toggle("Reveal recovered (synthetic) passwords", value=False)
    if not reveal:
        df["recovered_password"] = df["recovered_password"].apply(
            lambda v: "[redacted]" if v else "")
    st.dataframe(df, width="stretch", hide_index=True)

    st.markdown("#### Recommendations")
    for rec in s["recommendations"]:
        st.markdown(f"- {rec}")

    st.info("Open the **Reports** page (sidebar) to download a PDF / CSV / JSON "
            "report for this run.")

ui.sidebar_notice()
