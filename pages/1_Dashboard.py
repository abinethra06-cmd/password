import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import plotly.express as px
import streamlit as st

import config
import ui_helpers as ui
from backend import database as db

st.set_page_config(page_title="Dashboard", page_icon=":material/dashboard:",
                   layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/dashboard: Security Dashboard")

runs = db.list_runs()
datasets = db.list_datasets()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Datasets", len(datasets))
c2.metric("Audits", len(runs))
total_cracked = sum(r["cracked_count"] for r in runs)
total_hashes = sum(r["total_hashes"] for r in runs)
c3.metric("Total recovered", total_cracked)
c4.metric("Across target hashes", total_hashes)

if not runs:
    st.info("No audits yet. Run one from the **Run Audit** page.")
    st.stop()

# --- Aggregate risk levels across all runs' results ------------------------
all_results = []
for r in runs:
    for res in db.get_results(r["id"]):
        res = dict(res)
        res["dataset_name"] = r["dataset_name"]
        res["attack_type"] = r["attack_type"]
        all_results.append(res)
rdf = pd.DataFrame(all_results)

left, right = st.columns(2)

with left:
    st.subheader("Risk distribution")
    counts = (rdf["risk_level"].fillna("Low").value_counts()
              .reindex(config.RISK_LEVELS).fillna(0).reset_index())
    counts.columns = ["risk_level", "count"]
    fig = px.pie(counts, names="risk_level", values="count", hole=0.45,
                 color="risk_level", color_discrete_map=config.RISK_COLORS)
    fig.update_layout(height=340, margin=dict(t=10, b=10))
    st.plotly_chart(fig, width="stretch")

with right:
    st.subheader("Cracked vs. safe")
    rdf["status"] = rdf["cracked"].apply(lambda c: "Recovered" if c else "Resisted")
    sc = rdf["status"].value_counts().reset_index()
    sc.columns = ["status", "count"]
    fig2 = px.bar(sc, x="status", y="count", color="status",
                  color_discrete_map={"Recovered": "#b00020", "Resisted": "#2e7d32"})
    fig2.update_layout(height=340, margin=dict(t=10, b=10), showlegend=False)
    st.plotly_chart(fig2, width="stretch")

st.subheader("Crack rate by technique")
by_method = (rdf[rdf["cracked"] == 1].groupby("method").size()
             .reset_index(name="recovered"))
if not by_method.empty:
    fig3 = px.bar(by_method, x="method", y="recovered", color="method")
    fig3.update_layout(height=320, margin=dict(t=10, b=10), showlegend=False)
    st.plotly_chart(fig3, width="stretch")

st.subheader("Recent audits")
runs_df = pd.DataFrame(runs)[
    ["id", "dataset_name", "attack_type", "total_hashes", "cracked_count",
     "duration_sec", "started_at"]]
st.dataframe(runs_df, width="stretch", hide_index=True)

ui.sidebar_notice()
