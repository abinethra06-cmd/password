import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st

import config
import ui_helpers as ui
from backend import database as db, hashing
from backend.attacks import dictionary_attack, hybrid_attack, rainbow_table

st.set_page_config(page_title="Attacks", page_icon=":material/bolt:", layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/bolt: Attack Techniques (interactive)")
st.caption("Learn each technique and try it against synthetic hashes.")

ENGINES = {"dictionary": dictionary_attack.run, "hybrid": hybrid_attack.run,
           "rainbow": rainbow_table.run}


def _single_hash_runner(engine_key: str):
    st.markdown("**Try a single hash**")
    h = st.text_input("Hash (hex digest)", key=f"{engine_key}_h",
                      placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99")
    algo = st.selectbox("Algorithm", config.FAST_ALGOS, key=f"{engine_key}_a")
    if st.button("Attempt recovery", key=f"{engine_key}_btn") and h.strip():
        target = [{"id": 1, "username": "target", "hash_value": h.strip(),
                   "hash_algo": algo, "salt": None, "is_salted": False}]
        out = ENGINES[engine_key](target)
        r = out["results"][0]
        if r["cracked"]:
            st.success(f"Recovered: `{r['recovered_password']}`  "
                       f"(attempts: {r['attempts']}, {out['elapsed']:.3f}s)")
        else:
            st.error(f"Not recovered with {engine_key}. "
                     f"({out['attempts']} candidates tried, {out['elapsed']:.3f}s)")


def _dataset_runner(engine_key: str):
    if not ui.has_data():
        st.info("Generate synthetic data on the Home page to run against a dataset.")
        return
    opts = ui.dataset_options()
    label = st.selectbox("Dataset", list(opts.keys()), key=f"{engine_key}_ds")
    if st.button(f"Run {engine_key} on dataset", key=f"{engine_key}_run"):
        entries = db.get_entries(opts[label])
        targets = [{"id": e["id"], "username": e["username"],
                    "hash_value": e["hash_value"], "hash_algo": e["hash_algo"],
                    "salt": e["salt"], "is_salted": bool(e["is_salted"])}
                   for e in entries]
        out = ENGINES[engine_key](targets)
        st.write(f"Recovered **{out['cracked_count']}/{len(targets)}** "
                 f"in {out['elapsed']:.3f}s ({out['attempts']} candidates).")
        df = pd.DataFrame(out["results"])[
            ["username", "hash_algo", "cracked", "recovered_password"]]
        st.dataframe(df, width="stretch", hide_index=True)


tab_d, tab_h, tab_r = st.tabs(["Dictionary", "Hybrid", "Rainbow table"])

with tab_d:
    st.markdown(
        "Hashes every word in a wordlist and matches the digests against the "
        "target hashes. Fast and effective against common passwords.")
    st.caption("Limitation: can only find passwords that appear in the wordlist.")
    _dataset_runner("dictionary")
    st.divider()
    _single_hash_runner("dictionary")

with tab_h:
    st.markdown(
        "Mutates dictionary words with human patterns: capitalisation, leetspeak "
        "(a->@, e->3, o->0, s->$), and appended numbers, years and symbols. Catches "
        "passwords like `Summer2021`, `welcome1`, `p@$$w0rd`.")
    st.caption("Limitation: only rule-expressible mutations; candidate space grows "
               "quickly, so a per-word cap trades coverage for speed.")
    _dataset_runner("hybrid")
    st.divider()
    _single_hash_runner("hybrid")

with tab_r:
    st.markdown(
        "Precomputes a hash-to-password lookup table so recovery is an O(1) lookup "
        "with no hashing at attack time. This is the space-for-time idea behind "
        "rainbow tables.")
    st.caption("Limitation: storage grows with coverage; a direct lookup table "
               "(used here) is simpler than reduction-chain rainbow tables; and it "
               "is defeated by salting.")

    st.markdown("#### Salted vs. unsalted demonstration")
    col1, col2 = st.columns([2, 1])
    sample = col1.text_input("Sample word to demonstrate (synthetic, not stored)",
                             value="dragon")
    algo = col2.selectbox("Algorithm", config.FAST_ALGOS, key="demo_algo")
    if st.button("Demonstrate"):
        demo = rainbow_table.demonstrate_salting(sample, algo)
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Unsalted hash**")
            st.code(demo["unsalted"]["stored"], language="text")
            if demo["unsalted"]["cracked"]:
                st.error(f"Recovered instantly: `{demo['unsalted']['recovered']}`")
            else:
                st.warning("Not in table (word not in wordlist).")
        with d2:
            st.markdown("**Salted hash (PBKDF2)**")
            st.code(demo["salted"]["stored"], language="text")
            if demo["salted"]["cracked"]:
                st.error("Recovered (unexpected).")
            else:
                st.success("Lookup fails - salting defeats the precomputed table.")
        st.info(demo["conclusion"])

    st.divider()
    _dataset_runner("rainbow")

ui.sidebar_notice()
