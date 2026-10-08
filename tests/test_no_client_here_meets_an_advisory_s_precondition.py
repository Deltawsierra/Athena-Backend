"""This service's HTTP clients against the advisories registered for them
(advisories.toml): where an advisory's behaviour is reachable, it is shown not
to happen; where it is not, the precondition is shown to stay absent, so a
change that introduces it fails here rather than going unnoticed.

* GHSA-9hjg-9r4m-mvj7 (requests, CVE-2024-47081, fixed in 2.32.4): a Session
  that trusts the environment reads ~/.netrc, and below 2.32.4 it looked the
  login up by the URL's netloc cut at its first colon, so
  ``http://<netrc machine>:@<elsewhere>/`` sent that machine's login to
  <elsewhere>. The engine client calls requests directly; here its base URL is
  the advisory's shape, and what reaches the adapter is read.
* GHSA-34jh-p97f-mpxf (urllib3, CVE-2024-37891): a Proxy-Authorization header
  set by hand survived a cross-origin redirect. No client here sets one.
* GHSA-pq67-6m6q-mj2v (urllib3, CVE-2025-50181): redirects were followed though
  a PoolManager's retries disabled them. No client here builds a PoolManager.
"""

from __future__ import annotations

import base64
import re
import secrets
from pathlib import Path

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.utils import get_netrc_auth

ROOT = Path(__file__).resolve().parent.parent
MACHINE = "engine.test"


def _source_files():
    for path in sorted(ROOT.rglob("*.py")):
        parts = set(path.relative_to(ROOT).parts)
        if parts & {"tests", "migrations", "node_modules", ".git"}:
            continue
        yield path


@pytest.fixture
def netrc_for_one_host(tmp_path, monkeypatch):
    canary = "cnrynetrc" + secrets.token_hex(10)
    netrc = tmp_path / ".netrc"
    netrc.write_text(f"machine {MACHINE}\nlogin operator\npassword {canary}\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert get_netrc_auth(f"http://{MACHINE}/") == ("operator", canary)
    return canary


@pytest.mark.parametrize(
    "base_url",
    [f"http://{MACHINE}:@elsewhere.test", f"http://{MACHINE}:8099@elsewhere.test"],
)
def test_a_netrc_login_reaches_no_host_but_the_one_it_names(
    netrc_for_one_host, monkeypatch, base_url
):
    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

    sent: list[tuple[str, str | None]] = []

    def send(self, request, **kwargs):
        sent.append((request.url, request.headers.get("Authorization")))
        raise requests.ConnectionError("recorded at the adapter; nothing is sent")

    monkeypatch.setattr(HTTPAdapter, "send", send)
    client = CyberEngineClient(base_url=base_url, api_key="operator-key")
    with pytest.raises(EngineError):
        client._send_get("/health")
    assert sent, "the request never reached the adapter, so nothing was shown"
    for url, authorization in sent:
        carried = (
            base64.b64decode(authorization[6:]).decode("utf-8", "replace")
            if authorization and authorization.startswith("Basic ")
            else authorization or ""
        )
        assert netrc_for_one_host not in carried, (url, authorization)


def test_no_client_here_sets_a_proxy_credential_by_hand():
    setting = re.compile(r"""["']proxy-authorization["']""", re.IGNORECASE)
    found = [str(p.relative_to(ROOT)) for p in _source_files() if setting.search(p.read_text())]
    assert found == [], (
        f"{found} set a Proxy-Authorization header by hand: GHSA-34jh-p97f-mpxf "
        "applies to that use; register how it is protected"
    )


def test_no_client_here_disables_redirects_through_a_pool_manager():
    building = re.compile(r"\bPoolManager\(|\bProxyManager\(|urllib3\.request\(")
    found = [str(p.relative_to(ROOT)) for p in _source_files() if building.search(p.read_text())]
    assert found == [], (
        f"{found} drive urllib3 directly: GHSA-pq67-6m6q-mj2v applies to a PoolManager "
        "whose retries disable redirects; register how that use is protected"
    )
