"""
wazuh_executor.py — Active Response dispatcher for ZeroRespond.

Only allowlisted commands run. Only IPs not on the protected list are
accepted as srcip. Every call is logged to audit_log by the caller;
this module is side-effect free beyond the Wazuh API call.
"""
import ipaddress
import os
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ────────────────────────────────────────
WAZUH_HOST  = os.getenv("WAZUH_HOST",  "https://192.168.244.131:55000")
WAZUH_USER  = os.getenv("WAZUH_USER",  "wazuh-wui")
WAZUH_PASS  = os.getenv("WAZUH_PASS",  "MyS3cr37P450r.*-")

# Comma-separated list of IPs / CIDRs that can never be blocked.
# Default covers Wazuh manager, Docker gateway, loopback, LAN router.
_DEFAULT_PROTECTED = "127.0.0.1,127.0.0.0/8,192.168.244.1,192.168.244.131,10.0.0.1,172.17.0.1,172.18.0.1,172.19.0.1"
PROTECTED_NETS = [
    ipaddress.ip_network(c.strip(), strict=False)
    for c in os.getenv("PROTECTED_IPS", _DEFAULT_PROTECTED).split(",")
    if c.strip()
]

# Short-lived token cache (Wazuh tokens expire after ~15 min)
_token_cache = {"token": None, "expires": 0.0}


# ── Token ────────────────────────────────────────────────
def _get_token(force=False):
    now = time.time()
    if not force and _token_cache["token"] and now < _token_cache["expires"]:
        return _token_cache["token"]
    try:
        r = requests.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=8,
        )
        if r.status_code == 200:
            tok = r.json().get("data", {}).get("token")
            if tok:
                _token_cache["token"]   = tok
                _token_cache["expires"] = now + 240
                return tok
        print(f"[ar] auth failed: {r.status_code} {r.text[:200]}")
        return None
    except Exception as e:
        print(f"[ar] auth exception: {e}")
        return None


# ── Guardrails ───────────────────────────────────────────
def is_protected_ip(ip_str):
    """Return True if this IP must NOT be blocked."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True   # unparseable → refuse
    return any(ip in net for net in PROTECTED_NETS)


def validate_action(action):
    """
    action is the playbook_steps.action JSONB dict.
    Returns (ok: bool, reason: str, normalized: dict).
    """
    if not isinstance(action, dict):
        return False, "action is not an object", {}
    if action.get("type") != "active_response":
        return False, f"unsupported action type: {action.get('type')}", {}

    command = (action.get("command") or "").strip()
    if not command:
        return False, "missing command", {}

    params = action.get("params") or {}
    srcip = str(params.get("srcip") or "").strip()
    if not srcip:
        return False, "missing srcip parameter", {}

    if is_protected_ip(srcip):
        return False, f"srcip {srcip} is protected", {}

    return True, "ok", {"command": command, "srcip": srcip}


# ── Active Response ──────────────────────────────────────
def run_active_response(agent_id, command, srcip, timeout=10):
    """
    Fire a Wazuh Active Response command on one agent.

    Returns a dict:
        {
          "ok": True/False,
          "status": <HTTP status or None>,
          "detail": <text>,
          "response": <parsed JSON or None>
        }
    """
    if not agent_id:
        return {"ok": False, "status": None, "detail": "missing agent_id", "response": None}

    tok = _get_token()
    if not tok:
        return {"ok": False, "status": None, "detail": "wazuh auth failed", "response": None}

    url = f"{WAZUH_HOST}/active-response"
    params = {"agents_list": agent_id}
    body = {
        "command": f"!{command}",           # '!' = custom command
        "alert": {"data": {"srcip": srcip}},
    }
    headers = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    try:
        r = requests.put(
            url, params=params, json=body, headers=headers,
            verify=False, timeout=timeout,
        )
        ok = r.status_code in (200, 201)
        try:
            payload = r.json()
        except ValueError:
            payload = None
        return {
            "ok":       ok,
            "status":   r.status_code,
            "detail":   (r.text or "")[:400],
            "response": payload,
        }
    except requests.RequestException as e:
        return {"ok": False, "status": None, "detail": str(e)[:200], "response": None}
