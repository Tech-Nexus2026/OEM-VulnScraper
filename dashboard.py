import os
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="OEM Security Center",
    page_icon="🛡️",
    layout="wide"
)

DB_PATH = Path(__file__).parent / "vulnerabilities.db"

st.title("🛡️ OEM Security Center")
st.caption("OEM Vulnerability Monitoring and Alert Dashboard")

# Sidebar
st.sidebar.header("Dashboard Controls")

if st.sidebar.button("🔄 Refresh Dashboard"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("Email Configuration")

email_ready = all([
    os.getenv("SMTP_SERVER"),
    os.getenv("SENDER_EMAIL"),
    os.getenv("SENDER_PASSWORD"),
    os.getenv("RECEIVER_EMAIL")
])

if email_ready:
    st.sidebar.success("SMTP credentials configured")
else:
    st.sidebar.info("Email is in demo mode")

# Read database
@st.cache_data(ttl=5)
def load_data():
    if not DB_PATH.exists():
        return pd.DataFrame()

    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query(
            "SELECT * FROM vulnerabilities ORDER BY id DESC",
            conn
        )

data = load_data()

if data.empty:
    st.warning(
        "No vulnerabilities found. Run `python main.py` "
        "in your terminal first, then refresh this dashboard."
    )
    st.stop()

# Handle missing columns and values
expected_columns = [
    "name", "version", "oem", "severity", "description",
    "mitigation", "patch_url", "published_date",
    "unique_id", "source_url"
]

for column in expected_columns:
    if column not in data.columns:
        data[column] = "- NA -"

data[expected_columns] = (
    data[expected_columns]
    .fillna("- NA -")
    .astype(str)
)

data["severity"] = data["severity"].str.strip().str.capitalize()

# Summary cards
total = len(data)
critical = int((data["severity"] == "Critical").sum())
high = int((data["severity"] == "High").sum())

col1, col2, col3 = st.columns(3)

col1.metric("Total Records", total)
col2.metric("Critical Vulnerabilities", critical)
col3.metric("High Vulnerabilities", high)

st.markdown("---")

# Filters
st.subheader("🔎 Vulnerability Records")

filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    search_text = st.text_input(
        "Search product or CVE ID",
        placeholder="e.g. Chrome or CVE-2023-47131"
    )

with filter_col2:
    severity_filter = st.selectbox(
        "Filter by severity",
        ["All", "Critical", "High"]
    )

filtered = data.copy()

if search_text.strip():
    mask = (
        filtered["name"].str.contains(
            search_text, case=False, na=False
        )
        | filtered["unique_id"].str.contains(
            search_text, case=False, na=False
        )
    )
    filtered = filtered[mask]

if severity_filter != "All":
    filtered = filtered[
        filtered["severity"] == severity_filter
    ]

st.write(f"Showing **{len(filtered)}** matching record(s).")

display_columns = [
    "unique_id", "name", "version", "oem", "severity",
    "published_date"
]

st.dataframe(
    filtered[display_columns],
    use_container_width=True,
    hide_index=True
)

# Vulnerability details
st.markdown("---")
st.subheader("📋 Vulnerability Details")

if not filtered.empty:
    filtered = filtered.reset_index(drop=True)

    selected_index = st.selectbox(
        "Choose a record to inspect",
        options=list(range(len(filtered))),
        format_func=lambda i: (
            f"{filtered.loc[i, 'unique_id']} — "
            f"{filtered.loc[i, 'name']}"
        )
    )

    selected = filtered.iloc[selected_index]

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:
        st.write("**Product:**", selected["name"])
        st.write("**Version:**", selected["version"])
        st.write("**OEM:**", selected["oem"])
        st.write("**Severity:**", selected["severity"])
        st.write("**CVE / Unique ID:**", selected["unique_id"])

    with detail_col2:
        st.write("**Published date:**", selected["published_date"])
        st.write("**Description:**", selected["description"])
        st.write("**Mitigation:**", selected["mitigation"])

        patch_url = selected["patch_url"]
        source_url = selected["source_url"]

        if patch_url.startswith(("https://", "http://")):
            st.link_button("Open Patch URL", patch_url)

        if source_url.startswith(("https://", "http://")):
            st.link_button("Open Advisory Source", source_url)

else:
    st.info("No records match your current filters.")

st.markdown("---")
st.caption(
    "OEM-VulnScraper | Local SQLite data | "
    "Email status indicates configuration, not delivery."
)