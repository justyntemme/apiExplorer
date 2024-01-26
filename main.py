# -------------------------------------------------------------------------------------------
# init and references
# -------------------------------------------------------------------------------------------
import json
import logger
from typing import Tuple
import requests
import os
import csv


accessKey = os.environ.get("PC_IDENTITY")
accessSecret = os.environ.get("PC_SECRET")
base_url = os.environ.get("PC_URL")
api_version = "1"
csv.field_size_limit(10000000)


def prisma_cwp_login(
    base_url: str,
    api_version: str,
    access_key: str,  # Prisma generated access key
    secret_key: str,  # Prisma generated secret key
) -> Tuple[int, dict]:
    apiURL = f"{base_url}/api/v{api_version}/authenticate"
    apiHeader = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    apiBody = {"username": access_key, "password": secret_key}
    logger.logging.info("Generating PRISMA token using endpoint: %s", apiURL)
    response = requests.post(apiURL, headers=apiHeader, json=apiBody, timeout=60)
    if response.status_code == 200:
        data = json.loads(response.text)
        logger.logging.info("Token aquired")
        return 200, data
    logger.logging.error(
        "Unable to aquire PRISMA token with error code: %s", response.status_code
    )
    return response.status_code, None


def get_endpoint(
    base_url: str,
    api_version: str,
    api_endpoint: str,
    access_token: str,
    content_type: str,
) -> Tuple[int, dict]:
    apiURL = f"{base_url}/api/v{api_version}{api_endpoint}"
    apiHeader = {
        "Content-Type": "%s" % content_type,
        "Authorization": "Bearer %s" % access_token,
    }
    logger.logging.info(f"{apiURL} Request")
    response = requests.get(apiURL, headers=apiHeader)
    if response.status_code == 200:
        data = response.text
        return 200, data
    logger.logging.error(f"failed to query endpoint {apiURL}")


def post_endpoint(
    base_url: str,
    api_version: str,
    api_endpoint: str,
    access_token: str,
    content_type: str,
) -> Tuple[int, dict]:
    apiURL = f"{base_url}/api/v{api_version}{api_endpoint}"
    apiHeader = {
        "Content-Type": "%s" % content_type,
        "Authorization": "Bearer %s" % access_token,
    }
    logger.logging.info(f"{apiURL} Request")
    response = requests.get(apiURL, headers=apiHeader)
    if response.status_code == 200:
        data = response.text
        return 200, data
    logger.logging.error(f"failed to query endpoint {apiURL}")


# -------------------------------------------------------------------------------------------
# payload
# -------------------------------------------------------------------------------------------
pcToken = prisma_cwp_login(base_url, api_version, accessKey, accessSecret)
if pcToken[0] != 200:
    exit()
print(pcToken[1]["token"])

# pcData = prisma_cwp_logs(base_url, api_version, pcToken[1]["token"])
pcData = post_endpoint(
    base_url, api_version, api_endpoint, pcToken[1]["token"], "text/csv"
)
csv_reader = csv.reader(pcData[1].splitlines())

# -------------------------------------------------------------------------------------------
# data processing
# -------------------------------------------------------------------------------------------
desired_column_index = 4

unique_values = set()

for row in csv_reader:
    if row and len(row) > desired_column_index:
        unique_values.add(row[desired_column_index])

for value in unique_values:
    print(value)
