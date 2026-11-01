import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

import ui_helpers as ui
from backend import database as db, strength, weak_detector as wd

st.set_page_config(page_title="Password Strength", page_icon=":material/shield:",
                   layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/shield: Password Strength Evaluation")
st.caption("A transparent, rule-based assessment (no AI/ML). The password you "
           "type is analysed in memory and never stored.")

pw = st.text_input("Password to evaluate", type="password")
log_it = st.checkbox("Log the (non-identifying) metrics to history", value=True,
                     help="Stores only length, entropy, score and verdict - "
                          "never the password itself.")

if pw:
    common = wd.load_common_set()
    m = strength.analyze(pw, common_set=common, dictionary_set=common)

    c1, c2, c3 = st.columns(3)
    c1.metric("Score", f"{m['score']}/100", m["verdict"])
    c2.metric("Entropy", f"{m['entropy_bits']} bits")
    c3.metric("Est. offline crack time", m["crack_time_est"])

    st.progress(m["score"] / 100)

    d1, d2 = st.columns(2)
    with d1:
        st.markdown("**Composition**")
        st.write(f"- Length: {m['length']}")
        st.write(f"- Character types: {m['classes_present']}/4")
        st.write(f"- Effective charset: {m['charset_size']}")
    with d2:
        st.markdown("**Flags**")
        st.write(f"- Common password: {'yes' if m['is_common'] else 'no'}")
        st.write(f"- Dictionary word: {'yes' if m['is_dictionary_word'] else 'no'}")
        st.write(f"- Sequence/repeat: "
                 f"{'yes' if m['has_sequence'] or m['has_repeat'] else 'no'}")

    st.markdown("**Feedback**")
    for f in m["feedback"]:
        st.markdown(f"- {f}")

    if log_it:
        db.log_strength_check(m)
        st.caption("Metrics logged to history (no plaintext stored).")

with st.expander("How the score is computed"):
    st.markdown(
        "The score combines **length**, **character-class diversity** and "
        "**estimated entropy** (`length x log2(charset size)`), then subtracts "
        "penalties for common passwords, dictionary words, sequential runs "
        "(`abc`, `123`, `qwerty`), repeated characters, single-class passwords and "
        "date-like strings. Known common passwords are reported as crackable "
        "**instantly** regardless of entropy, because they fall to a dictionary "
        "attack in milliseconds.")

ui.sidebar_notice()
