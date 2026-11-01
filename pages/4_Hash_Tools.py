import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st

import config
import ui_helpers as ui
from backend import database as db, hashing
from backend import hash_identifier as hid

st.set_page_config(page_title="Hash Tools", page_icon=":material/tag:", layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/tag: Hash Tools")

tab_id, tab_verify, tab_gen = st.tabs(
    ["Identify hash", "Verify password", "Generate hash"])

with tab_id:
    st.markdown("Guess the algorithm behind a hash from its length and format. "
                "Several algorithms share a length, so results are ranked candidates.")
    value = st.text_input("Hash value", placeholder="paste a hash or digest")
    if value.strip():
        guesses = hid.identify(value.strip())
        db.log_hash_identification(value.strip(), guesses)
        st.dataframe(pd.DataFrame(guesses), width="stretch", hide_index=True)
        if hid.is_salted_format(value.strip()):
            st.success("This is a salted/slow format - resistant to precomputed "
                       "and batch attacks.")

with tab_verify:
    st.markdown("Verify whether a password matches a stored hash. The password is "
                "used **in memory only** and is never stored.")
    pw = st.text_input("Password candidate", type="password")
    stored = st.text_input("Stored hash",
                           placeholder="hex digest or pbkdf2_sha256$... / scrypt$...")
    algo = st.selectbox("Algorithm (for bare hex digests)",
                        ["auto"] + config.FAST_ALGOS)
    if st.button("Verify") and pw and stored.strip():
        a = None if algo == "auto" else algo
        match = hashing.verify(pw, stored.strip(), algo=a)
        if match:
            st.success("Match - the password produces this hash.")
        else:
            st.error("No match.")

with tab_gen:
    st.markdown("Generate a hash from a sample value (useful for building your own "
                "authorized test data). Synthetic use only.")
    text = st.text_input("Value to hash", value="password")
    cols = st.columns(2)
    with cols[0]:
        st.markdown("**Fast (unsalted) digests**")
        rows = [{"algorithm": a, "digest": hashing.compute(text, a)}
                for a in config.FAST_ALGOS]
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    with cols[1]:
        st.markdown("**Salted (secure) KDFs**")
        st.code("PBKDF2: " + hashing.hash_pbkdf2(text), language="text")
        st.code("scrypt: " + hashing.hash_scrypt(text), language="text")
        st.caption("Re-run to see a new random salt each time.")

ui.sidebar_notice()
