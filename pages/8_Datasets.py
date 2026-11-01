import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st

import config
import ui_helpers as ui
from backend import database as db, dataset_import as di

st.set_page_config(page_title="Datasets", page_icon=":material/database:",
                   layout="wide")
ui.bootstrap()
ui.require_ack()

st.title(":material/database: Datasets")
st.caption("Create a dataset to audit. Use only synthetic data or hashes you are "
           "authorized to test.")


def _preview_and_create(rows, errors, key):
    for e in errors:
        st.warning(e)
    if not rows:
        st.info("Nothing to import yet.")
        return
    st.success(f"{len(rows)} account(s) parsed.")
    df = pd.DataFrame(rows)[["username", "hash_algo", "is_salted", "hash_value"]]
    st.dataframe(df, width="stretch", hide_index=True)
    c1, c2 = st.columns(2)
    name = c1.text_input("Dataset name", key=f"{key}_name")
    desc = c2.text_input("Description", key=f"{key}_desc", value="")
    if st.button(":material/add: Create dataset", key=f"{key}_btn", type="primary"):
        try:
            did = di.create_dataset(name, desc, rows)
            st.success(f"Created dataset #{did} '{name}' with {len(rows)} accounts.")
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))


tab_hash, tab_plain, tab_manage = st.tabs(
    ["From hashes (CSV / paste)", "From sample passwords", "Manage datasets"])

# --- Tab 1: existing hashes -----------------------------------------------
with tab_hash:
    st.markdown("Provide hashes you are **authorized** to audit. The algorithm is "
                "auto-detected from each hash's length/format when not specified.")
    up = st.file_uploader(
        "Upload a CSV (columns: hash_value, and optionally username, hash_algo, "
        "salt, is_salted)", type=["csv"])
    pasted = st.text_area(
        "...or paste hashes, one per line (optionally `username:hash`)",
        height=140, placeholder="alice:5f4dcc3b5aa765d61d8327deb882cf99\n"
        "e10adc3949ba59abbe56e057f20f883e")
    algo_choice = st.selectbox("Algorithm for pasted hashes",
                               ["auto"] + config.FAST_ALGOS, index=0)

    rows, errors = [], []
    if up is not None:
        text = up.getvalue().decode("utf-8", errors="ignore")
        rows, errors = di.rows_from_csv(text)
    elif pasted.strip():
        rows, errors = di.rows_from_hashes(pasted, algo=algo_choice)
    _preview_and_create(rows, errors, "hash")

# --- Tab 2: hash plaintext here -------------------------------------------
with tab_plain:
    st.markdown("Type **sample passwords** and the tool hashes them here, so you "
                "can build authorized synthetic test data without providing real "
                "secrets.")
    algo = st.selectbox("Store as", config.FAST_ALGOS + config.SECURE_ALGOS,
                        index=config.FAST_ALGOS.index("md5"),
                        help="Fast algos are crackable; salted KDFs resist attacks.")
    text = st.text_area(
        "One per line: `username,password` or just `password`",
        height=160, placeholder="alice,password\nbob,Summer2021\nletmein")
    rows, errors = ([], [])
    if text.strip():
        rows, errors = di.rows_from_plaintext(text, algo=algo)
    _preview_and_create(rows, errors, "plain")

# --- Tab 3: manage ---------------------------------------------------------
with tab_manage:
    datasets = db.list_datasets()
    if not datasets:
        st.info("No datasets yet.")
    else:
        st.dataframe(
            pd.DataFrame(datasets)[
                ["id", "name", "description", "source", "entry_count", "created_at"]],
            width="stretch", hide_index=True)
        labels = {f'[{d["id"]}] {d["name"]}': d["id"] for d in datasets}
        target = st.selectbox("Delete a dataset", list(labels.keys()))
        st.caption("Deleting a dataset also removes its audit runs and results.")
        if st.button(":material/delete: Delete", type="secondary"):
            db.delete_dataset(labels[target])
            st.success(f"Deleted {target}.")
            st.rerun()

ui.sidebar_notice()
