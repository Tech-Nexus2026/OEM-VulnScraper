import streamlit as st

st.set_page_config(
    page_title="About OEM-VulnScraper",
    page_icon="ℹ️",
    layout="wide"
)

st.title("ℹ️ About OEM-VulnScraper")

st.subheader("OEM Vulnerability Monitoring & Alert System")

st.markdown("---")

st.header("🎯 Project Objective")

st.write(
    """
    OEM-VulnScraper is designed to help monitor software
    vulnerabilities, analyze vulnerability information,
    store important records, and provide security alerts.
    """
)

st.markdown("---")

st.header("⚙️ System Workflow")

st.write(
    """
    1. Vulnerability data is collected.

    2. The collected information is parsed and normalized.

    3. Vulnerability records are stored in the database.

    4. Live vulnerability information can be searched.

    5. Vulnerabilities are classified according to severity.

    6. Critical and High vulnerabilities can generate email alerts.
    """
)

st.markdown("---")

st.header("🛠️ Technologies Used")

col1, col2 = st.columns(2)

with col1:
    st.write(
        """
        **Programming & Application**
        
        • Python  
        • Streamlit  
        • SQLite
        """
    )

with col2:
    st.write(
        """
        **Security & Data**
        
        • NIST NVD  
        • CVE  
        • CVSS  
        • SMTP Email Alerting
        """
    )

st.markdown("---")

st.header("🔐 Security Features")

st.write(
    """
    • Live vulnerability search

    • CVE identification

    • CVSS score information

    • Critical / High / Medium / Low monitoring

    • Local vulnerability database

    • Email alerting for important vulnerabilities
    """
)

st.markdown("---")

st.header("📊 Project Components")

st.write(
    """
    **Person 1:** Vulnerability data collection / scraping

    **Person 2:** Vulnerability parsing and analysis

    **Person 3:** Email alerting and reporting

    **Person 4:** Integration, testing, dashboard and deployment
    """
)

st.markdown("---")

st.caption(
    "OEM-VulnScraper | Final Year Project"
)