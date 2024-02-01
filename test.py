import unittest
import os
from main import prisma_login, make_request
import json


class TestAPIRequests(unittest.TestCase):
    def setUp(self):
        self.access_key = os.environ.get("PC_IDENTITY")
        self.access_secret = os.environ.get("PC_SECRET")

    def login_and_test_request(self, url, api_version, method, data=None):
        _, login_response = prisma_login(url, "1", self.access_key, self.access_secret)
        token = login_response["token"]
        response_code, _ = make_request(
            url,
            "1",
            token,
            "application/json",
            method,
            data if data else None,
        )
        return response_code

    def test_get_cloud_inventory(self):
        url = "https://api0.prismacloud.io/cloud"
        response_code = self.login_and_test_request(url, "1", "GET")
        self.assertEqual(response_code, 200)

    def test_get_images(self):
        url = "https://app0.cloud.twistlock.com/panw-app0-310/api/v1/images"
        response_code = self.login_and_test_request(url, "1", "GET")
        self.assertEqual(response_code, 200)

    def test_post_inventory(self):
        url = "https://api0.prismacloud.io/v3/inventory"
        data = {
            "detailed": True,
            "fields": ["string"],
            "filters": [
                {
                    "name": "string",
                    "operator": "tag:yaml.org,2002:value =",
                    "value": "string",
                }
            ],
            "groupBy": ["string"],
            "limit": 0,
            "offset": 0,
            "pageToken": "string",
            "sortBy": ["string"],
        }
        print(json.dumps(data))
        response_code = self.login_and_test_request(url, "1", "POST", data)
        self.assertEqual(response_code, 200)


if __name__ == "__main__":
    unittest.main()
