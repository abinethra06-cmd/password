"""Shared helpers for the Streamlit UI: path bootstrap, DB init, auth gate."""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st

import config
from backend import database as db

RISK_COLORS = config.RISK_COLORS


def bootstrap():
    """Ensure the schema exists; safe to call on every page load."""
    db.init_db()


def sidebar_notice():
    st.sidebar.markdown("---")
    st.sidebar.caption(
        "Authorized security testing only. All datasets are synthetic. "
        "Strength checks never store the password you type.")


def require_ack():
    """Gate tool pages behind the Home-page acknowledgement."""
    if not st.session_state.get("acknowledged"):
        st.warning("Please read and accept the authorized-use notice on the "
                   "**Home** page (sidebar) before using the tools.")
        st.stop()


def dataset_options() -> dict:
    """Map 'label' -> dataset_id for selectboxes."""
    opts = {}
    for d in db.list_datasets():
        opts[f'[{d["id"]}] {d["name"]}  ({d["entry_count"]} accounts)'] = d["id"]
    return opts


def has_data() -> bool:
    return len(db.list_datasets()) > 0


def risk_badge(level: str) -> str:
    color = RISK_COLORS.get(level, "#777")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;' \
           f'border-radius:10px;font-size:0.8em">{level}</span>'
