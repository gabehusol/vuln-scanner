from __future__ import annotations

import re

import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def build_session(user_agent: str, verify_tls: bool, retries: int) -> requests.Session:
    retry = Retry(
        total=retries,
        backoff_factor=0.4,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=25, pool_maxsize=25)

    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": user_agent})
    session.verify = certifi.where() if verify_tls else False
    return session


def extract_title(body: str) -> str:
    match = TITLE_PATTERN.search(body or "")
    if not match:
        return ""
    return " ".join(match.group(1).split())[:120]
