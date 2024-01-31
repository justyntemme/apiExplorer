import json
import logging
import requests
import os
import csv
import argparse
from typing import Tuple, Optional
from urllib.parse import urlparse, urlunparse

logging.basicConfig(level=logging.INFO)


def get_base_url(full_url: str) -> str:
    parsed_url = urlparse(full_url)
    # Construct the base URL by keeping only the scheme, netloc, and path (up to the second last segment)
    path_segments = parsed_url.path.split("/")
    base_path = "/".join(path_segments[:-2])  # Remove the last two segments
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, base_path, "", "", ""))
    return base_url


def return_hostname(url: str) -> str:
    parsed_url = urlparse(url)
    return parsed_url.hostname


def is_twistlock_in_url(url: str) -> bool:
    """
    Checks if 'twistlock' is in the hostname of the URL.

    Parameters:
    url (str): The URL to be checked.

    Returns:
    bool: True if 'twistlock' is in the hostname, False otherwise.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return "twistlock" in hostname if hostname else False


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
    response = requests.post(apiURL, headers=headers, json=body, timeout=60)
    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data
    logging.error("Unable to acquire token with error code: %s", response.status_code)
    return response.status_code, None


def make_request(
    url: str,
    api_version: str,
    access_token: str,
    content_type: str,
    method: str,
    data: Optional[dict],
) -> Tuple[int, Optional[str]]:
    headers = {
        "Content-Type": content_type,
        "Authorization": f"Bearer {access_token}",
    }
    logging.info(f"Making {method} request to {url}")

    if method.upper() == "GET":
        response = requests.get(url, headers=headers)
    elif method.upper() == "POST":
        response = requests.post(url, headers=headers, json=data)
    else:
        logging.error(f"Invalid request method: {method}")
        return 405, None

    if response.status_code == 200:
        return 200, response.text
    else:
        logging.error(
            f"Failed to query endpoint {url} with status code: {response.status_code}"
        )
        return response.status_code, None


def main():
    parser = argparse.ArgumentParser(
        description="Script to interact with Prisma Cloud API."
    )
    parser.add_argument(
        "--type", type=str, required=True, help="Request Type (GET/POST/PUT)"
    )
    parser.add_argument(
        "--url", type=str, required=True, help="Request URL overrides default"
    )

    args = parser.parse_args()

    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    base_url = os.environ.get("TL_URL")
    api_version = "1"
    csv.field_size_limit(10000000)

    pcToken = prisma_login(args.url, api_version, accessKey, accessSecret)

    if pcToken[0] != 200:
        exit()
    logging.info("Token: %s", pcToken[1]["token"])

    pcData = make_request(
        args.url, api_version, pcToken[1]["token"], "text/csv", args.type, None
    )
    if pcData[0] != 200:
        exit()
    print(pcData[1])


if __name__ == "__main__":
    main()
