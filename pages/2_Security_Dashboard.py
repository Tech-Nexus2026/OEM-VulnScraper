import os
import sqlite3
from pathlib import Path

import pandas as pd
import requests
import streamlit as st


st.set_page_config(
    page_title="OEM Security Center",
    page_icon="🛡️",
    layout="wide"
)


DB_PATH = Path(__file__).parent / "vulnerabilities.db"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def get_value(value):
    """Return a clean value or - NA -."""
    if value is None:
        return "- NA -"

    value = str(value).strip()

    if value == "":
        return "- NA -"

    return value


def get_description(cve):
    """Get English CVE description."""
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return get_value(item.get("value"))

    return "- NA -"


def get_severity(cve):
    """Get the best available CVSS severity."""

    metrics = cve.get("metrics", {})

    # Prefer CVSS v4
    if metrics.get("cvssMetricV40"):
        data = metrics["cvssMetricV40"][0].get("cvssData", {})

        severity = data.get("baseSeverity")

        if severity:
            return severity.capitalize()

    # Then CVSS v3.1
    if metrics.get("cvssMetricV31"):
        data = metrics["cvssMetricV31"][0].get("cvssData", {})

        severity = data.get("baseSeverity")

        if severity:
            return severity.capitalize()

    # Then CVSS v3.0
    if metrics.get("cvssMetricV30"):
        data = metrics["cvssMetricV30"][0].get("cvssData", {})

        severity = data.get("baseSeverity")

        if severity:
            return severity.capitalize()

    # Finally CVSS v2
    if metrics.get("cvssMetricV2"):
        data = metrics["cvssMetricV2"][0].get("cvssData", {})

        score = data.get("baseScore")

        if score is not None:

            score = float(score)

            if score >= 9.0:
                return "Critical"

            elif score >= 7.0:
                return "High"

            elif score >= 4.0:
                return "Medium"

            else:
                return "Low"

    return "- NA -"


def get_score(cve):
    """Get the best available CVSS score."""

    metrics = cve.get("metrics", {})

    # CVSS v4
    if metrics.get("cvssMetricV40"):
        return metrics["cvssMetricV40"][0].get(
            "cvssData", {}
        ).get("baseScore", "- NA -")

    # CVSS v3.1
    if metrics.get("cvssMetricV31"):
        return metrics["cvssMetricV31"][0].get(
            "cvssData", {}
        ).get("baseScore", "- NA -")

    # CVSS v3.0
    if metrics.get("cvssMetricV30"):
        return metrics["cvssMetricV30"][0].get(
            "cvssData", {}
        ).get("baseScore", "- NA -")

    # CVSS v2
    if metrics.get("cvssMetricV2"):
        return metrics["cvssMetricV2"][0].get(
            "cvssData", {}
        ).get("baseScore", "- NA -")

    return "- NA -"


def get_reference(cve):
    """Get the first available reference URL."""

    references = cve.get("references", [])

    if references:
        return get_value(references[0].get("url"))

    return "- NA -"


def get_product_from_cpe(cve):
    """
    Try to extract a product name from the
    CPE configuration information.
    """

    def search_nodes(nodes):
        for node in nodes:
            matches = node.get("cpeMatch", [])

            for match in matches:
                criteria = match.get("criteria", "")

                parts = criteria.split(":")

                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]

                    vendor = vendor.replace("_", " ")
                    product = product.replace("_", " ")

                    return f"{vendor} {product}"

            children = node.get("children", [])

            result = search_nodes(children)

            if result:
                return result

        return None

    configurations = cve.get("configurations", [])

    for configuration in configurations:
        result = search_nodes(
            configuration.get("nodes", [])
        )

        if result:
            return result

    return "- NA -"


# ---------------------------------------------------------
# Live NVD search
# ---------------------------------------------------------

def search_nvd(search_term):
    """
    Search the NIST National Vulnerability Database.
    """

    search_term = search_term.strip()

    if not search_term:
        return []

    headers = {
        "User-Agent": "OEM-VulnScraper-Student-Project/1.0"
    }

    params = {
        "resultsPerPage": 20
    }

    # If user searches a CVE ID
    if search_term.upper().startswith("CVE-"):
        params["cveId"] = search_term.upper()

    else:
        params["keywordSearch"] = search_term

    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=20
        )

        if response.status_code == 403:
            st.error(
                "NVD temporarily rejected the request. "
                "Please wait a little and try again."
            )
            return []

        if response.status_code != 200:
            st.error(
                f"NVD API returned HTTP {response.status_code}."
            )
            return []

        result = response.json()

        vulnerabilities = result.get(
            "vulnerabilities",
            []
        )

        records = []

        for item in vulnerabilities:

            cve = item.get("cve", {})

            cve_id = get_value(
                cve.get("id")
            )

            published = get_value(
                cve.get("published")
            )

            if published != "- NA -":
                published = published[:10]

            severity = get_severity(cve)

            score = get_score(cve)

            description = get_description(cve)

            reference = get_reference(cve)

            product = get_product_from_cpe(cve)

            records.append({
                "unique_id": cve_id,
                "name": product
                    if product != "- NA -"
                    else search_term,
                "version": "- NA -",
                "oem": "- NA -",
                "severity": severity,
                "cvss_score": score,
                "description": description,
                "mitigation": (
                    "Check the official vendor advisory "
                    "and update to a secure version."
                ),
                "patch_url": reference,
                "published_date": published,
                "source_url": reference
            })

        return records

    except requests.exceptions.Timeout:

        st.error(
            "The NVD request timed out. "
            "Please try again."
        )

        return []

    except requests.exceptions.RequestException as error:

        st.error(
            f"Could not connect to NVD: {error}"
        )

        return []

    except Exception as error:

        st.error(
            f"Unexpected error: {error}"
        )

        return []


# ---------------------------------------------------------
# Load local database
# ---------------------------------------------------------

@st.cache_data(ttl=5)
def load_database():

    if not DB_PATH.exists():
        return pd.DataFrame()

    with sqlite3.connect(DB_PATH) as conn:

        return pd.read_sql_query(
            "SELECT * FROM vulnerabilities ORDER BY id DESC",
            conn
        )


# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------

st.title("🛡️ OEM Security Center")

st.caption(
    "OEM Vulnerability Monitoring and Alert Dashboard"
)


# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------

st.sidebar.header("Dashboard Controls")


if st.sidebar.button("🔄 Refresh Dashboard"):

    st.cache_data.clear()

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

    st.sidebar.success(
        "SMTP credentials configured"
    )

else:

    st.sidebar.info(
        "Email is in demo mode"
    )


# ---------------------------------------------------------
# LIVE VULNERABILITY SEARCH
# ---------------------------------------------------------

st.markdown("---")

st.header("🌐 Live Vulnerability Search")

st.write(
    "Search the NIST National Vulnerability Database "
    "for vulnerabilities affecting a product, vendor, "
    "technology, or CVE ID."
)


with st.form("nvd_search_form"):

    search_term = st.text_input(
        "Enter product, vendor, technology or CVE ID",
        placeholder=(
            "Example: Chrome, Firefox, Cisco, "
            "Windows, WordPress or CVE-2024-1234"
        )
    )

    search_button = st.form_submit_button(
        "🔎 Search Live Vulnerabilities"
    )


if search_button:

    if not search_term.strip():

        st.warning(
            "Please enter something to search."
        )

    else:

        with st.spinner(
            f"Searching NVD for '{search_term}'..."
        ):

            live_results = search_nvd(
                search_term
            )

        if live_results:

            st.success(
                f"Found {len(live_results)} "
                f"vulnerability record(s)."
            )

            live_df = pd.DataFrame(
                live_results
            )

            # Summary
            critical_count = int(
                (
                    live_df["severity"]
                    .str.lower()
                    == "critical"
                ).sum()
            )

            high_count = int(
                (
                    live_df["severity"]
                    .str.lower()
                    == "high"
                ).sum()
            )

            medium_count = int(
                (
                    live_df["severity"]
                    .str.lower()
                    == "medium"
                ).sum()
            )

            col1, col2, col3, col4 = st.columns(4)

            col1.metric(
                "Results",
                len(live_df)
            )

            col2.metric(
                "Critical",
                critical_count
            )

            col3.metric(
                "High",
                high_count
            )

            col4.metric(
                "Medium",
                medium_count
            )

            st.markdown("---")

            st.subheader(
                "🔐 Live Vulnerability Results"
            )

            display_columns = [
                "unique_id",
                "name",
                "severity",
                "cvss_score",
                "published_date"
            ]

            st.dataframe(
                live_df[display_columns],
                use_container_width=True,
                hide_index=True
            )

            # Detailed results
            st.markdown("---")

            st.subheader(
                "📋 Vulnerability Details"
            )

            selected_id = st.selectbox(
                "Select a vulnerability",
                live_df["unique_id"].tolist()
            )

            selected = live_df[
                live_df["unique_id"]
                == selected_id
            ].iloc[0]

            detail_col1, detail_col2 = st.columns(2)

            with detail_col1:

                st.write(
                    "**CVE ID:**",
                    selected["unique_id"]
                )

                st.write(
                    "**Product:**",
                    selected["name"]
                )

                st.write(
                    "**Severity:**",
                    selected["severity"]
                )

                st.write(
                    "**CVSS Score:**",
                    selected["cvss_score"]
                )

                st.write(
                    "**Published Date:**",
                    selected["published_date"]
                )

            with detail_col2:

                st.write(
                    "**Description:**",
                    selected["description"]
                )

                st.write(
                    "**Recommended Action:**",
                    selected["mitigation"]
                )

                source_url = selected["source_url"]

                if source_url.startswith(
                    ("https://", "http://")
                ):

                    st.link_button(
                        "Open NVD Reference",
                        source_url
                    )

        else:

            st.warning(
                f"No vulnerability records found "
                f"for '{search_term}'."
            )


# ---------------------------------------------------------
# LOCAL DATABASE
# ---------------------------------------------------------

st.markdown("---")

st.header("💾 Stored Vulnerability Records")

data = load_database()


if data.empty:

    st.info(
        "No locally stored vulnerabilities found."
    )

else:

    expected_columns = [
        "name",
        "version",
        "oem",
        "severity",
        "description",
        "mitigation",
        "patch_url",
        "published_date",
        "unique_id",
        "source_url"
    ]

    for column in expected_columns:

        if column not in data.columns:

            data[column] = "- NA -"


    data[expected_columns] = (
        data[expected_columns]
        .fillna("- NA -")
        .astype(str)
    )


    data["severity"] = (
        data["severity"]
        .str.strip()
        .str.capitalize()
    )


    total = len(data)

    critical = int(
        (
            data["severity"]
            == "Critical"
        ).sum()
    )

    high = int(
        (
            data["severity"]
            == "High"
        ).sum()
    )


    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Stored Records",
        total
    )

    col2.metric(
        "Critical Vulnerabilities",
        critical
    )

    col3.metric(
        "High Vulnerabilities",
        high
    )


    filter_col1, filter_col2 = st.columns(2)


    with filter_col1:

        local_search = st.text_input(
            "Search stored records",
            placeholder="Chrome or CVE ID"
        )


    with filter_col2:

        local_severity = st.selectbox(
            "Filter stored records",
            ["All", "Critical", "High"]
        )


    filtered = data.copy()


    if local_search.strip():

        mask = (
            filtered["name"].str.contains(
                local_search,
                case=False,
                na=False
            )
            |
            filtered["unique_id"].str.contains(
                local_search,
                case=False,
                na=False
            )
        )

        filtered = filtered[mask]


    if local_severity != "All":

        filtered = filtered[
            filtered["severity"]
            == local_severity
        ]


    st.write(
        f"Showing **{len(filtered)}** "
        f"stored record(s)."
    )


    st.dataframe(
        filtered[
            [
                "unique_id",
                "name",
                "version",
                "oem",
                "severity",
                "published_date"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )


st.markdown("---")

st.caption(
    "OEM-VulnScraper | NIST NVD Live Search | "
    "Local SQLite Database | Email Alerting"
)