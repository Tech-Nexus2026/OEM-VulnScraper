from scraper import poll_oem_portal
from parser import parse_vulnerability
from database import save_vulnerability
from email_reporter import send_email_alert


def main():
    print("\n[MAIN] Starting OEM Vulnerability Pipeline...")

    # Step 1: Get vulnerability from scraper
    raw_record = poll_oem_portal()

    # Step 2: Send scraped data to parser
    parsed_record = parse_vulnerability(raw_record)

    if parsed_record:
        print("\n[MAIN] Vulnerability successfully processed.")

        for key, value in parsed_record.items():
            print(f"{key}: {value}")
        save_vulnerability(parsed_record)
        send_email_alert(parsed_record)
    else:
        print("\n[MAIN] Vulnerability was rejected by the parser.")


if __name__ == "__main__":
    main()