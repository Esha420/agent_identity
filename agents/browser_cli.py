#!/usr/bin/env python3
"""Browser Agent CLI - Navigates to target URL and extracts page title & metadata."""

import argparse
import json
import os
import sys
import httpx
from bs4 import BeautifulSoup


def main():
    parser = argparse.ArgumentParser(description="Browser Agent CLI")
    parser.add_argument("--url", default=os.getenv("TARGET_URL", "http://localhost:8089"), help="Target URL to visit")
    parser.add_argument("--goal", default="Retrieve page title", help="Agent goal")
    args = parser.parse_args()

    print(f"[*] Browser Agent starting goal: '{args.goal}' on {args.url}")
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.get(args.url)
            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else "No Title Found"
            h1 = soup.find("h1")
            h1_text = h1.get_text().strip() if h1 else ""

            result = {
                "status": "COMPLETED",
                "url": str(resp.url),
                "title": title,
                "h1": h1_text,
                "status_code": resp.status_code,
            }

            print(f"[+] Successfully extracted: title='{title}', h1='{h1_text}'")
            print("--- RESULT JSON ---")
            print(json.dumps(result, indent=2))

            # Persist output artifact
            os.makedirs("/workspace", exist_ok=True)
            with open("/workspace/result.json", "w") as f:
                json.dump(result, f, indent=2)

    except Exception as e:
        print(f"[-] Browser Agent failed to fetch {args.url}: {e}", file=sys.stderr)
        err_res = {"status": "FAILED", "url": args.url, "error": str(e)}
        print(json.dumps(err_res))
        sys.exit(1)


if __name__ == "__main__":
    main()
