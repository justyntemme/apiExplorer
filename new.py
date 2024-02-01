import json
import logging
import requests
import os
import csv
import argparse
from typing import Tuple, Optional
from urllib.parse import urlparse, urlunparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(level=logging.INFO)

# Suppress only the single InsecureRequestWarning from urllib3 needed
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_base_url(full_url: str) -> str:
    parsed_url = urlparse(full_url)
    # Construct the base URL by keeping only the scheme, netloc, and path (up to the second last segment)
    path_segments = parsed_url.path.split("/")
    base_path = "/".join(path_segments[:-2])  # Remove the last two segments
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, base_path, "", "", ""))
    return base_url


def is_twistlock_in_url(url: str) -> bool:
    """Checks if 'twistlock' is in the hostname of the URL."""
    return "twistlock" in urlparse(url).hostname



def prisma_login(
    base_url: str, api_version: str, access_key: str, secret_key: str
) -> Tuple[int, dict]:
    base_url = get_base_url(base_url)
    if is_twistlock_in_url(base_url):
        apiURL = f"{base_url}/v1/authenticate"
    else:
        apiURL = f"{base_url}/login"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": access_key, "password": secret_key}
    logging.info("Generating token using endpoint: %s", apiURL)
    response = requests.post(
        apiURL, headers=headers, json=body, timeout=60, verify=False
    )
    if response.status_code == 404:
        print("You are probably forgetting /api/v1 prior to your endpoint ")
    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data
    logging.error("Unable to acquire token with error code: %s", response.status_code)
    return response.status_code, None


def make_request(
    url: str, access_token: str, content_type: str, method: str, data: Optional[dict]
) -> Tuple[int, Optional[str]]:
    """Makes a request to the given URL with specified parameters."""
    headers = {"Content-Type": content_type, "Authorization": f"Bearer {access_token}"}
    logging.info(f"Making {method} request to {url}")
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, verify=False)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data, verify=False)
        else:
            logging.error(f"Invalid request method: {method}")
            return 405, None
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return 500, None

    if response.status_code == 200:
        return 200, response.text
    logging.error(
        f"Failed to query endpoint {url} with status code: {response.status_code}"
    )
    return response.status_code, None


def main():
    parser = argparse.ArgumentParser(
        description="Script to interact with Prisma Cloud API."
    )
    parser.add_argument(
        "--type", choices=["GET", "POST"], required=True, help="Request type"
    )
    parser.add_argument("--url", required=True, help="Request URL")
    parser.add_argument("--data", type=json.loads, help="JSON object for request body")
    parser.add_argument(
        "--json", action="store_true", help="Set content type to application/json"
    )
    parser.add_argument(
        "--csv", action="store_true", help="Set content type to text/csv"
    )

    args = parser.parse_args()
    content_type = "application/json" if args.json else "text/csv"

    access_key = os.environ.get("PC_IDENTITY")
    access_secret = os.environ.get("PC_SECRET")
    api_version = "1"

    if not all([access_key, access_secret]):
        logging.error("Missing required environment variables")
        exit(1)

    pc_token = prisma_login(args.url, api_version, access_key, access_secret)
    if pc_token[0] != 200:
        exit(pc_token[0])

    response = make_request(
        args.url, pc_token[1]["token"], content_type, args.type, args.data
    )
    if response[0] != 200:
        exit(response[0])

    print(response[1])


if __name__ == "__main__":
    main()
