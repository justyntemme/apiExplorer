import json
import logging
import requests
import os
import csv
from typing import Tuple, Optional
import argparse

# Setup basic logging
logging.basicConfig(level=logging.INFO)


def prisma_cwp_login(
    base_url: str, api_version: str, access_key: str, secret_key: str
) -> Tuple[int, dict]:
    apiURL = f"{base_url}/api/v{api_version}/authenticate"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": access_key, "password": secret_key}
    logging.info("Generating PRISMA token using endpoint: %s", apiURL)
    response = requests.post(apiURL, headers=headers, json=body, timeout=60)
    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data
    logging.error(
        "Unable to acquire PRISMA token with error code: %s", response.status_code
    )
    return response.status_code, None


def make_request(
    base_url: str,
    api_version: str,
    api_endpoint: str,
    access_token: str,
    content_type: str,
    method: str = "GET",
    data: Optional[dict] = None,
) -> Tuple[int, Optional[str]]:
    apiURL = f"{base_url}/api/v{api_version}{api_endpoint}"
    headers = {
        "Content-Type": content_type,
        "Authorization": f"Bearer {access_token}",
    }
    logging.info(f"Making {method} request to {apiURL}")

    if method.upper() == "GET":
        response = requests.get(apiURL, headers=headers)
    elif method.upper() == "POST":
        response = requests.post(apiURL, headers=headers, json=data)
    else:
        logging.error(f"Invalid request method: {method}")
        return 405, None

    if response.status_code == 200:
        return 200, response.text
    else:
        logging.error(
            f"Failed to query endpoint {apiURL} with status code: {response.status_code}"
        )
        return response.status_code, None


def main():
    parser = argparse.ArgumentParser(
        description="Script to interact with Prisma Cloud API."
    )
    parser.add_argument("--endpoint", type=str, required=True, help="API endpoint")
    parser.add_argument(
        "--type", type=str, required=True, help="Request Type (GET/POST/PUT)"
    )
    args = parser.parse_args()

    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    base_url = os.environ.get("TL_URL")
    api_version = "1"
    csv.field_size_limit(10000000)

    pcToken = prisma_cwp_login(base_url, api_version, accessKey, accessSecret)
    if pcToken[0] != 200:
        exit()
    logging.info("Token: %s", pcToken[1]["token"])

    pcData = make_request(
        base_url, api_version, args.endpoint, pcToken[1]["token"], "text/csv", args.type
    )
    if pcData[0] != 200:
        exit()

    csv_reader = csv.reader(pcData[1].splitlines())
    desired_column_index = 4
    unique_values = set()

    for row in csv_reader:
        if row and len(row) > desired_column_index:
            unique_values.add(row[desired_column_index])

    for value in unique_values:
        print(value)


if __name__ == "__main__":
    main()
