"""Password Security Auditing Tool -- Streamlit entry point (Home).

Run:  python -m streamlit run app.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

import config
import ui_helpers as ui
from backend import database as db
from scripts import generate_test_data as gen

st.set_page_config(page_title=config.APP_TITLE, page_icon=":material/lock:",
                   layout="wide")
ui.bootstrap()

st.title(":material/lock: " + config.APP_TITLE)
st.caption(config.APP_TAGLINE)

# --- Authorized-use notice + acknowledgement -------------------------------
with st.container(border=True):
    st.subheader(":material/gavel: Authorized Use Notice")
    st.markdown(
        """
This application is for **authorized password security assessment and
education** only. It is designed for use by security teams, administrators and
students on systems and data they are **explicitly permitted** to test.

- It operates entirely **offline** on **synthetic datasets** and local test hashes.
- It performs **no account access** and collects **no real credentials**.
- The password-strength checker evaluates passwords **in memory** and never
  stores the plaintext.

Using password-recovery techniques against systems or data you are not
authorized to test may be **illegal**. You are responsible for ensuring you
have permission.
        """)
    ack = st.checkbox(
        "I confirm I am authorized to perform this testing and will use this "
        "tool only against synthetic or explicitly permitted data.",
        value=st.session_state.get("acknowledged", False))
    st.session_state["acknowledged"] = ack
    if ack:
        st.success("Acknowledged. All tools in the sidebar are now unlocked.")

# --- Quick status ----------------------------------------------------------
datasets = db.list_datasets()
runs = db.list_runs()

c1, c2, c3 = st.columns(3)
c1.metric("Synthetic datasets", len(datasets))
c2.metric("Audits run", len(runs))
c3.metric("Accounts loaded", sum(d["entry_count"] for d in datasets))

if not datasets:
    st.info("No synthetic test data yet. Generate it to explore the tool.")
    if st.button(":material/database: Generate synthetic datasets", type="primary"):
        with st.spinner("Building wordlist and seeding synthetic hashes..."):
            summary = gen.seed()
        st.success(f"Seeded {len(summary['datasets'])} datasets "
                   f"({summary['wordlist_size']}-word wordlist).")
        st.rerun()
else:
    with st.expander("Regenerate / reset synthetic data"):
        st.write("This rebuilds the wordlist and re-seeds all synthetic "
                 "datasets, clearing existing audit history.")
        if st.button(":material/refresh: Reset & reseed"):
            with st.spinner("Reseeding..."):
                gen.seed()
            st.success("Synthetic data reset.")
            st.rerun()

# --- What this does --------------------------------------------------------
st.markdown("### What you can do here")
colA, colB = st.columns(2)
with colA:
    st.markdown(
        "- **Run Audit** - test a dataset with dictionary, hybrid, rainbow, or all\n"
        "- **Attacks** - learn each technique and try it interactively\n"
        "- **Hash Tools** - identify a hash type; verify a password (no storage)")
with colB:
    st.markdown(
        "- **Password Strength** - rule-based strength meter and advice\n"
        "- **Reports** - download PDF / CSV / JSON audit reports\n"
        "- **History** - review past audits and strength checks")

st.markdown("### Techniques & their limits")
with st.expander("Dictionary attack"):
    st.write("Hashes each word in a list and matches against target hashes. "
             "**Limit:** only finds passwords present in the wordlist.")
with st.expander("Hybrid attack"):
    st.write("Mutates dictionary words (capitalisation, leetspeak, appended "
             "numbers/years/symbols). **Limit:** only rule-expressible mutations; "
             "the candidate space grows quickly.")
with st.expander("Rainbow-table attack"):
    st.write("Uses a precomputed hash-to-password lookup table for O(1) recovery "
             "of unsalted hashes. **Limit:** storage grows with coverage and it is "
             "**defeated by salting**. This tool uses a direct lookup table, not "
             "reduction-chain rainbow tables.")

ui.sidebar_notice()
