import json
import logging
import requests
import os
import argparse
from typing import Tuple, Optional
from urllib.parse import urlparse, urlunparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(level=logging.INFO)

# Suppress only the single InsecureRequestWarning from urllib3 needed
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Interact with Prisma Cloud API.")
    parser.add_argument("--url", required=True, help="The API URL to interact with.")
    parser.add_argument(
        "--type",
        choices=["GET", "POST", "PUT"],
        required=True,
        help="HTTP method to use.",
    )
    parser.add_argument(
        "--data",
        help="JSON payload for POST/PUT requests.",
        type=json.loads,
        default={},
    )

    content_type_group = parser.add_mutually_exclusive_group()
    content_type_group.add_argument(
        "--csv",
        action="store_true",
        help="Set Content-Type to text/csv. \
              Defaults to application/json if --csv is not present",
    )

    return parser.parse_args()


def get_base_url(full_url: str) -> str:
    parsed_url = urlparse(full_url)
    # Construct the base URL by keeping only the scheme, netloc
    # and path (up to the second last segment)
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
    url: str, api_version: str, access_key: str, secret_key: str
) -> Tuple[int, dict]:
    base_url = get_base_url(url)
    if is_twistlock_in_url(base_url):
        apiURL = f"{base_url}/v1/authenticate"
    else:
        base_url = return_hostname(base_url)
        apiURL = f"https://{base_url}/login"
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
        print(
            "You are probably forgetting \
             /api/v1[2,3] prior to your endpoint"
        )
    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data
    else:
        logging.error(
            "Unable to acquire token with error code: %s", response.status_code
        )

    return response.status_code, None


def make_request(
    url: str,
    api_version: str,
    access_token: str,
    content_type: str,
    method: str,
    data: Optional[json.loads],
) -> Tuple[int, Optional[str]]:
    headers = {
        "Content-Type": content_type,
    }
    if is_twistlock_in_url(url):
        headers["Authorization"] = f"Bearer {access_token}"
    else:
        headers["x-redlock-auth"] = f"{access_token}"
    logging.info(f"Making {method} request to {url}")

    if method.upper() == "GET":
        response = requests.get(url, headers=headers, verify=False)
    elif method.upper() == "POST":
        response = requests.post(url, headers=headers, verify=False, json=data)
    else:
        logging.error(f"Invalid request method: {method}")
        return 405, None

    if response.status_code == 200:
        return 200, response.text
    else:
        logging.error(
            f"Failed to query endpoint\
              {url} with status code: {response.status_code}"
        )
        return response.status_code, None


def main():
    args = parse_arguments()
    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    if not all([accessKey, accessSecret]):
        logging.error(
            "Missing required environment variables: PC_IDENTITY or PC_SECRET."
        )
        exit(1)

    api_version = "1"

    pcToken = prisma_login(args.url, api_version, accessKey, accessSecret)
    if pcToken[0] != 200:
        logging.error("Error aquiring token %s", pcToken[0])
        exit()
    if args.csv:
        pcData = make_request(
            args.url, api_version, pcToken[1]["token"], "text/csv", args.type, args.data
        )
    else:
        pcData = make_request(
            args.url,
            api_version,
            pcToken[1]["token"],
            "application/json",
            args.type,
            args.data,
        )
    if pcData[0] != 200:
        exit()
    print(pcData[1])


if __name__ == "__main__":
    main()
