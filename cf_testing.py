import requests
import time


import os
import json
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


config = {
    'cf_url': "d3hb8km1omxgyh.cloudfront.net",
    'cf_id': "EUGX9LMZXAHYK",

}


class CookieSigner(object):

    CF_URL = "d3hb8km1omxgyh.cloudfront.net"
    CF_ID = "EUGX9LMZXAHYK"
    CF_KP_ID = 'APKAJCPCBU2AODA4AW6A'
    TP_ALL = "/*"
    DURATION = 60 * 60 * 8
    RSA_KEY_PATH = "/home/andrej/cf_keys/pk-APKAJCPCBU2AODA4AW6A.pem"

    def __init__(self, team_space, ip_address=None, date_gt=None, date_lt=None):
        self.tp = team_space
        self.ip = ip_address
        self.dt_gt = date_gt
        self.dt_lt = date_lt
        self.now = datetime.utcnow()

    @staticmethod
    def time_limit_validation(input_):
        if isinstance(input_, datetime):
            return int(input_.timestamp())
        elif isinstance(input_, int):
            return int(
                (datetime.utcnow() + timedelta(seconds=input_)).timestamp()
            )

    def valid_until(self):
        if self.dt_lt is None:
            return (self.now + timedelta(seconds=self.DURATION)).timestamp()
        return self.time_limit_validation(self.dt_lt)

    def valid_from(self):
        if self.dt_gt is None:
            return int(self.now.timestamp())
        return self.time_limit_validation(self.dt_gt)

    def make_policy_map(self):
        return {
            "Statement": [{
                "Resource": f'https://{self.CF_URL}/{self.tp}/*',
                "Condition": {
                    "IpAddress": {"AWS:SourceIp": self.ip},
                    "DateGreaterThan": {"AWS:EpochTime": self.valid_from()},
                    "DateLessThan": {"AWS:EpochTime": self.valid_until()}
                }
            }]
        }

    def filter_policy_map(self):
        pm = self.make_policy_map()
        condition = pm["Statement"][0]["Condition"]
        if self.ip is None:
            condition.pop("IpAddress")
            pm["Statement"][0]["Condition"] = condition

        return pm

    def get_policy_map(self):
        return self.filter_policy_map()

    def get_policy_json(self):
        return json.dumps(self.get_policy_map()).replace(" ", "")

    def get_policy_b64(self):
        return self.replace_invalid_chars(
            str(base64.b64encode(
                self.get_policy_json().encode("utf-8")), "utf-8"
            )
        )

    @staticmethod
    def replace_invalid_chars(signed_hash):
        return signed_hash.replace("+", "-").replace("=", "_").replace("/", "~")

    def generate_cookies(self, policy, signature):
        return {
            "CloudFront-Policy": policy,
            "CloudFront-Signature": signature,
            "CloudFront-Key-Pair-Id": self.CF_KP_ID
        }

    def __str__(self):
        return str(self.get_policy_map()).replace(" ", "")

    def __repr__(self):
        from_dt = datetime.fromtimestamp(self.valid_from())
        to_dt = datetime.fromtimestamp(self.valid_until())
        return "tp: {}; ip: {}; valid from: {}; to: {}; duration: {}".format(
            self.tp,
            self.ip,
            from_dt,
            to_dt,
            to_dt - from_dt
        )

    def rsa_signer(self):
        with open(self.RSA_KEY_PATH, "rb") as pk:
            private_key = serialization.load_pem_private_key(
                pk.read(),
                password=None,
                backend=default_backend()
            )
            signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1())
            signer.update(self.get_policy_json().encode("utf-8"))
            return signer.finalize()

    def generate_signature(self):
        """
        Creates a signature for the policy from the key, returning a string
        """
        sig_bytes = self.rsa_signer()
        sig_64 = self.replace_invalid_chars(
            str(base64.b64encode(sig_bytes), "utf-8"))
        return sig_64

    def generate_signed_cookies(self):
        signature = self.generate_signature()
        return self.generate_cookies(self.get_policy_b64(), signature)

    def build_url(self, object_uri):
        return self.CF_URL + os.sep + self.tp + os.sep + object_uri

    def generate_curl_cmd(self, object_uri):
        """
        Generates a cURL command (use for testing)
        :param object_uri: location of object you'd like to get
            example:
                'images/image1.png'
        :return:
        """
        curl_cmd = "curl -v"
        for k, v in self.generate_signed_cookies().items():
            curl_cmd += " -H 'Cookie: {}={}'".format(k, v)
        curl_cmd += " {}".format(self.build_url(object_uri))
        return curl_cmd


o = CookieSigner(
        team_space="eu1_andrej_business_space",
        date_lt=60*60*4
    )

sig_cookies = o.generate_signed_cookies()

cf_url = "https://d3sdfds55sd5fkm1omxgyh.cloudfront.net"

s = requests.Session()

start = time.time()
r = s.get(
    cf_url +
    "/andrej-dev/eu1_andrej_business_space/images/0242fde34aafed9edfa00f5a0f8576321116a62119123dd8d7b947d0703eaee3-w300.jpg",
    cookies=sig_cookies,
    stream=True
)
print("request took:", time.time() - start)

if r.status_code == 200:
    with open("/home/andrej/retrieved10", "wb") as f:
        for chunk in r.iter_content(chunk_size=1024):
            f.write(chunk)

print(r)
print(r.content)
print(r.headers)
