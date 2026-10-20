"""A Financial Exposure Receipt is signed with the engine's receipt-signer key, and
never with the operator key (s28 audit, T10).

``receipt_service.engine_signer`` and ``engine_keyring`` built
``CyberEngineClient.from_settings()``, whose one credential is the engine OPERATOR
key: the key that runs and aborts scans and approves deployments. So any analyst's
``"receipt": true`` put that key in play. They now build
``CyberEngineClient.for_receipt_signing()``, which holds the key the engine issues
for its sign route alone, read by its literal setting name
(``CYBERENGINE_ECONOMICS_SIGNER_KEY``). Held here, over the receipt service's
real path to the engine's HTTP client:

- signing presents the receipt-signer key on the sign route, and the operator
  key reaches no request;
- the keyring is read with the receipt-signer key too;
- with no receipt-signer key configured, signing answers what it always answered
  with no engine credential (``signer_unavailable``, ``RuntimeError``), nothing
  is recorded, and nothing at all is sent -- it never falls back to the operator
  key, configured throughout;
- the stop path keeps the operator key: ``from_settings`` is unchanged, and the
  receipt-signing client is built by the receipt service alone.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from django.test import override_settings
from mythos_core import exposure_receipt as core

from ai_engine.services.cyberengine_client import CyberEngineClient
from assurance.economics import receipt_service
from assurance.economics.models import FinancialExposureReceipt
from assurance.models import Deployment
from safety import outbound
from tests.test_economics_validity_card import _http, carded

pytestmark = pytest.mark.django_db

User = get_user_model()

ENGINE = "https://engine.test"
OPERATOR_KEY = "ce_op_operator-key-for-the-signer-tests"
SIGNER_KEY = "ce_rs_signer-key-for-the-signer-tests"
SIGN_ROUTE = "/api/economics/exposure-receipt/sign"
KEYRING_ROUTE = "/api/assurance/keyring"


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture
def receipt_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def engine(monkeypatch, receipt_key):
    """The engine at the far side of the backend's own HTTP client: every request
    the client sends is recorded with its headers. The sign route answers an
    envelope signed with ``receipt_key``; the keyring route, that key's role."""
    sent = []

    def post(url, **kwargs):
        sent.append(("POST", url, dict(kwargs.get("headers") or {})))
        return _http(200, core.sign_receipt(kwargs["json"]["receipt"], receipt_key))

    def get(url, **kwargs):
        sent.append(("GET", url, dict(kwargs.get("headers") or {})))
        return _http(200, _published(receipt_key))

    monkeypatch.setattr(outbound, "post", post)
    monkeypatch.setattr(outbound, "get", get)
    return sent


def _published(receipt_key):
    """A keyring as the engine publishes one: the artifact key, and the
    economics-receipt role's own."""
    artifact = Ed25519PrivateKey.generate()

    def entry(key):
        material = base64.b64encode(_raw(key)).decode("ascii")
        return {"public_key": material, "status": "active"}

    return {
        "version": 1,
        "keys": {"sha256:" + "a" * 32: entry(artifact)},
        "roles": {core.ECONOMICS_RECEIPT_ROLE: {"version": 1, "keys": {"sha256:" + "b" * 32: entry(receipt_key)}}},
    }


def _credentials(sent) -> list[str]:
    return [headers.get("X-API-Key") for _method, _url, headers in sent]


def _no_operator_key(sent) -> None:
    for _method, _url, headers in sent:
        assert OPERATOR_KEY not in headers.values(), headers


both_keys = override_settings(
    CYBERENGINE_URL=ENGINE,
    CYBERENGINE_OPERATOR_KEY=OPERATOR_KEY,
    CYBERENGINE_ECONOMICS_SIGNER_KEY=SIGNER_KEY,
)
operator_key_only = override_settings(
    CYBERENGINE_URL=ENGINE,
    CYBERENGINE_OPERATOR_KEY=OPERATOR_KEY,
    CYBERENGINE_ECONOMICS_SIGNER_KEY="",
)


@both_keys
def test_a_receipt_is_signed_with_the_receipt_signer_key_and_the_keyring_read_with_it(
    deployment, people, engine, receipt_key
):
    """The receipt service's own path, keyring and signer from the engine: both
    requests carry the receipt-signer key, and neither carries the operator key."""
    result, _ = carded(deployment, people)
    keyring = receipt_service.engine_keyring()
    assert type(keyring) is core.ReceiptKeyring
    outcome = receipt_service.issue_receipt(result, keyring=keyring)
    assert outcome.created, (outcome.code, outcome.detail)

    assert [(method, url) for method, url, _ in engine] == [
        ("GET", ENGINE + KEYRING_ROUTE),
        ("POST", ENGINE + SIGN_ROUTE),
    ]
    assert _credentials(engine) == [SIGNER_KEY, SIGNER_KEY]
    _no_operator_key(engine)


@operator_key_only
def test_without_a_signer_key_signing_is_refused_as_before_and_never_with_the_operator_key(
    deployment, people, engine, receipt_key
):
    """The operator key is configured and would sign: the engine accepts it on the
    sign route still. Signing is refused as it was with no engine credential --
    ``signer_unavailable``, the error's type alone -- nothing is recorded, and no
    request leaves at all. The keyring is not read either."""
    result, _ = carded(deployment, people)
    ring = core.receipt_keyring([_raw(receipt_key)], other_roles={})
    outcome = receipt_service.issue_receipt(result, keyring=ring)
    assert outcome.receipt is None
    assert (outcome.code, outcome.detail) == ("signer_unavailable", "RuntimeError")
    assert not FinancialExposureReceipt.objects.exists()

    with pytest.raises(RuntimeError, match="CYBERENGINE_ECONOMICS_SIGNER_KEY is not configured"):
        receipt_service.engine_keyring()
    with pytest.raises(RuntimeError, match="CYBERENGINE_ECONOMICS_SIGNER_KEY is not configured"):
        receipt_service.engine_signer({"receipt_id": "x"})
    assert engine == [], "a request left with no signer key configured"


@both_keys
def test_the_stop_path_keeps_the_operator_key():
    """Every other call -- the scans, their stops, approvals -- builds
    ``from_settings`` and presents the operator key, as before, whatever the
    receipt-signer key is."""
    assert CyberEngineClient.from_settings().headers["X-API-Key"] == OPERATOR_KEY
    assert CyberEngineClient.for_receipt_signing().headers["X-API-Key"] == SIGNER_KEY


def test_the_receipt_signing_client_is_built_by_the_receipt_service_alone():
    """Used for signing only: the receipt service is the one module that builds
    the receipt-signing client, so no other call -- a stop least of all -- can
    present the receipt-signer key, and the key is read in one place, by its
    literal name."""
    root = Path(__file__).resolve().parent.parent
    builders, readers = set(), set()
    for path in root.rglob("*.py"):
        relative = path.relative_to(root).as_posix()
        if relative.startswith(("tests/", ".venv/", "venv/", "node_modules/")) or "settings" in relative:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"\.for_receipt_signing\(\)", text):
            builders.add(relative)
        if "CYBERENGINE_ECONOMICS_SIGNER_KEY" in text:
            readers.add(relative)
    assert builders == {"assurance/economics/receipt_service.py"}, builders
    assert readers == {"ai_engine/services/cyberengine_client.py"}, readers
