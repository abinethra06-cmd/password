import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st

import ui_helpers as ui
from backend import database as db

st.set_page_config(page_title="History", page_icon=":material/history:",
                   layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/history: Testing History")

tab_runs, tab_strength = st.tabs(["Audit runs", "Strength checks"])

with tab_runs:
    runs = db.list_runs()
    if not runs:
        st.info("No audit runs recorded yet.")
    else:
        df = pd.DataFrame(runs)[
            ["id", "dataset_name", "attack_type", "total_hashes", "cracked_count",
             "duration_sec", "status", "started_at", "finished_at"]]
        st.dataframe(df, width="stretch", hide_index=True)

        sel = st.selectbox("Inspect a run's results",
                           [r["id"] for r in runs], format_func=lambda i: f"Run #{i}")
        results = db.get_results(sel)
        if results:
            rdf = pd.DataFrame(results)[
                ["username", "hash_algo", "cracked", "method", "risk_level",
                 "attempts"]]
            st.dataframe(rdf, width="stretch", hide_index=True)

with tab_strength:
    checks = db.list_strength_checks()
    if not checks:
        st.info("No strength checks logged yet. (The Password Strength page can "
                "log non-identifying metrics.)")
    else:
        df = pd.DataFrame(checks)[
            ["checked_at", "length", "entropy_bits", "score", "verdict",
             "crack_time_est"]]
        st.dataframe(df, width="stretch", hide_index=True)
        st.caption("Only derived metrics are stored - never the password itself.")

ui.sidebar_notice()
