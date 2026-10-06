from parser import parse_vulnerability


def test_high_vulnerability():
    record = {
        "name": "Chrome",
        "severity": "High",
        "unique_id": "CVE-2023-47131"
    }

    result = parse_vulnerability(record)

    assert result is not None
    assert result["severity"] == "High"

    print("[TEST PASSED] High vulnerability accepted.")


def test_critical_vulnerability():
    record = {
        "name": "Chrome",
        "severity": "Critical",
        "unique_id": "CVE-2023-47132"
    }

    result = parse_vulnerability(record)

    assert result is not None
    assert result["severity"] == "Critical"

    print("[TEST PASSED] Critical vulnerability accepted.")


def test_low_vulnerability():
    record = {
        "name": "Chrome",
        "severity": "Low",
        "unique_id": "CVE-2023-47133"
    }

    result = parse_vulnerability(record)

    assert result is None

    print("[TEST PASSED] Low vulnerability rejected.")


if __name__ == "__main__":
    print("\n[TEST] Starting pipeline tests...\n")

    test_high_vulnerability()
    test_critical_vulnerability()
    test_low_vulnerability()

    print("\n[TEST] All tests completed successfully.")