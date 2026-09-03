import re
from database import save_vulnerability


def clean_text(value):
    """Remove extra spaces and handle empty values."""
    if value is None or str(value).strip() == "":
        return "- NA -"

    return re.sub(r"\s+", " ", str(value)).strip()


def get_severity(record):
    """Get severity from the raw record."""
    severity = record.get("severity", "- NA -")
    return clean_text(severity).capitalize()


def parse_vulnerability(record):
    """
    Takes raw vulnerability data and converts it
    into a standard format.
    """

    severity = get_severity(record)

    # Accept only Critical and High vulnerabilities
    if severity not in ["Critical", "High"]:
        print(f"[REJECTED] Severity '{severity}' is not allowed.")
        return None

    cleaned_data = {
        "name": clean_text(record.get("name")),
        "version": clean_text(record.get("version")),
        "oem": clean_text(record.get("oem")),
        "severity": severity,
        "description": clean_text(record.get("description")),
        "mitigation": clean_text(record.get("mitigation")),
        "patch_url": clean_text(record.get("patch_url")),
        "published_date": clean_text(record.get("published_date")),
        "unique_id": clean_text(record.get("unique_id")),
        "source_url": clean_text(record.get("source_url"))
    }

    print(f"[ACCEPTED] {severity}/High vulnerability")
    return cleaned_data


# -----------------------------
# TEST DATA
# -----------------------------

if __name__ == "__main__":

    
    raw_record = {
        "name": "Chrome",
        "version": "120.0",
        "severity": "Critical",
        "description": "A security vulnerability was found in Chrome.",
        "mitigation": "Update Chrome to the latest version.",
        "patch_url": "https://example.com/patch",
        "published_date": "2023-11-15",
        "unique_id": "CVE-2023-47131",
        "source_url": "https://example.com/advisory"
    }

    print("\nRaw Data:")
    print(raw_record)

    result = parse_vulnerability(raw_record)

    print("\nCleaned Data:")

    if result:
        for key, value in result.items():
            print(f"{key}: {value}")
        save_vulnerability(result)   

