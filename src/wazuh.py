"""Wazuh API helpers with cached bearer token."""
import time

import requests

from .config import WAZUH_HOST, WAZUH_USER, WAZUH_PASS

_token_cache = {"token": None, "expires": 0.0}


def get_wazuh_token(force=False):
    now = time.time()
    if not force and _token_cache["token"] and now < _token_cache["expires"]:
        return _token_cache["token"]
    try:
        res = requests.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=8,
        )
        if res.status_code == 200:
            token = res.json().get("data", {}).get("token")
            if token:
                _token_cache["token"]   = token
                _token_cache["expires"] = now + 240
                return token
        print(f"[wazuh] auth failed: {res.status_code} - {res.text[:200]}")
        return None
    except Exception as e:
        print(f"[wazuh] auth exception: {e}")
        return None


def wazuh_headers():
    tok = get_wazuh_token()
    if not tok:
        raise RuntimeError("Wazuh authentication failed")
    return {"Authorization": f"Bearer {tok}"}


def wazuh_get(path, params=None, timeout=8):
    r = requests.get(
        f"{WAZUH_HOST}{path}",
        headers=wazuh_headers(),
        params=params or {},
        verify=False,
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()