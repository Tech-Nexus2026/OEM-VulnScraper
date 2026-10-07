import streamlit as st

st.set_page_config(
    page_title="OEM-VulnScraper",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ OEM-VulnScraper")

st.subheader("OEM Vulnerability Monitoring & Alert System")

st.markdown("---")

st.header("Detect. Analyze. Protect.")

st.write(
    """
    OEM-VulnScraper is a security monitoring system designed
    to search, analyze, store, and report software vulnerabilities.
    """
)

st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("🔎 Live Search")
    st.write(
        "Search real vulnerability information "
        "from the NIST National Vulnerability Database."
    )

with col2:
    st.subheader("📊 Security Dashboard")
    st.write(
        "View vulnerabilities according to "
        "Critical, High, Medium, and Low severity."
    )

with col3:
    st.subheader("📧 Email Alerts")
    st.write(
        "Generate alerts for Critical and High "
        "severity vulnerabilities."
    )

st.markdown("---")

st.header("🚀 Project Workflow")

st.write(
    """
    Vulnerability Source → Scraper → Parser → Database
    → Security Dashboard → Email Alert
    """
)

st.markdown("---")

st.header("🛡️ About the System")

st.write(
    """
    The system helps security teams monitor software
    vulnerabilities and quickly identify important
    security issues.
    """
)

st.info(
    "Use the pages in the left sidebar to explore "
    "vulnerability search and the security dashboard."
)

st.markdown("---")

st.caption(
    "OEM-VulnScraper | Vulnerability Monitoring System"
)