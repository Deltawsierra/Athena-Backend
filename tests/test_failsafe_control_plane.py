"""Failsafe control plane: draft -> sign (two-person) -> ready -> engine polls.

Uses the real mythos-core operator signer to produce ed25519 signatures, so the
test proves the control plane's verification and the engine's would agree.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from mythos_core.failsafe.sign import keygen, sign_draft

User = get_user_model()

# Two enrolled operators.
ALICE_PRIV, ALICE_PUB = keygen()
BOB_PRIV, BOB_PUB = keygen()
KEYRING = {"alice": ALICE_PUB, "bob": BOB_PUB}
POLL_TOKEN = "test-poll-token"

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _failsafe_settings(settings):
    settings.FAILSAFE_OPERATOR_KEYS = KEYRING
    settings.FAILSAFE_POLL_TOKEN = POLL_TOKEN
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600


def _user(role):
    return User.objects.create_user(username=f"u_{role}_{User.objects.count()}",
                                    password="x", role=role)


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


def _draft_fields(resp_data):
    return {k: resp_data[k] for k in
            ("action", "engine_id", "nonce", "issued_at", "expires_at", "reason")}


def test_viewer_cannot_draft_but_analyst_can():
    viewer = _client(_user(User.Roles.VIEWER))
    assert viewer.post("/api/failsafe/commands/",
                       {"action": "pause", "engine_id": "athena-1"}, format="json").status_code == 403
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.post("/api/failsafe/commands/",
                     {"action": "pause", "engine_id": "athena-1"}, format="json")
    assert r.status_code == 201
    assert r.data["status"] == "awaiting_signatures"
    assert "signing_bytes" in r.data and r.data["required_signatures"] == 1


def test_pause_becomes_ready_with_one_signature():
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.post("/api/failsafe/commands/",
                     {"action": "pause", "engine_id": "athena-1"}, format="json")
    uuid = r.data["uuid"]
    sig = sign_draft(_draft_fields(r.data), key_id="alice", private_hex=ALICE_PRIV)
    r2 = analyst.post(f"/api/failsafe/commands/{uuid}/signatures/", sig, format="json")
    assert r2.status_code == 200, r2.data
    assert r2.data["status"] == "ready"
    assert r2.data["signers"] == ["alice"]


def test_stand_down_needs_two_distinct_signatures():
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.post("/api/failsafe/commands/",
                     {"action": "stand_down", "engine_id": "athena-1"}, format="json")
    uuid = r.data["uuid"]
    fields = _draft_fields(r.data)
    assert r.data["required_signatures"] == 2

    one = analyst.post(f"/api/failsafe/commands/{uuid}/signatures/",
                       sign_draft(fields, key_id="alice", private_hex=ALICE_PRIV), format="json")
    assert one.data["status"] == "awaiting_signatures", "one signature must not be ready"

    two = analyst.post(f"/api/failsafe/commands/{uuid}/signatures/",
                       sign_draft(fields, key_id="bob", private_hex=BOB_PRIV), format="json")
    assert two.data["status"] == "ready"
    assert set(two.data["signers"]) == {"alice", "bob"}


def test_the_same_operator_signing_twice_is_not_two_people():
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.post("/api/failsafe/commands/",
                     {"action": "terminate", "engine_id": "athena-1"}, format="json")
    # terminate is admin-only to initiate
    assert r.status_code == 403
    admin = _client(_user(User.Roles.ADMIN))
    r = admin.post("/api/failsafe/commands/",
                   {"action": "terminate", "engine_id": "athena-1"}, format="json")
    uuid, fields = r.data["uuid"], _draft_fields(r.data)
    admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
               sign_draft(fields, key_id="alice", private_hex=ALICE_PRIV), format="json")
    dup = admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
                     sign_draft(fields, key_id="alice", private_hex=ALICE_PRIV), format="json")
    assert dup.status_code == 409  # already signed
    detail = admin.get(f"/api/failsafe/commands/{uuid}/").data
    assert detail["status"] == "awaiting_signatures"


def test_an_invalid_signature_is_rejected():
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.post("/api/failsafe/commands/",
                     {"action": "pause", "engine_id": "athena-1"}, format="json")
    uuid = r.data["uuid"]
    bad = analyst.post(f"/api/failsafe/commands/{uuid}/signatures/",
                       {"key_id": "alice", "sig": "00" * 64}, format="json")
    assert bad.status_code == 400


def test_pending_requires_the_poll_token_and_serves_ready_commands():
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.post("/api/failsafe/commands/",
                     {"action": "pause", "engine_id": "athena-1"}, format="json")
    uuid, fields = r.data["uuid"], _draft_fields(r.data)
    analyst.post(f"/api/failsafe/commands/{uuid}/signatures/",
                 sign_draft(fields, key_id="alice", private_hex=ALICE_PRIV), format="json")

    anon = APIClient()
    assert anon.get("/api/failsafe/pending/").status_code == 401
    ok = anon.get("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    assert ok.status_code == 200
    cmds = ok.data
    assert len(cmds) == 1 and cmds[0]["nonce"] == fields["nonce"]
    # The served command verifies against the engine's own verify path.
    from mythos_core.failsafe import Command, NonceLedger, verify_command
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ring = {"alice": Ed25519PublicKey.from_public_bytes(bytes.fromhex(ALICE_PUB))}
    assert verify_command(Command.from_dict(cmds[0]), keyring=ring,
                          engine_id="athena-1", nonces=NonceLedger())


def test_state_surfaces_the_engine_live_governor_state(monkeypatch):
    from ai_engine.services import cyberengine_client

    class _Stub:
        def failsafe_state(self):
            return {"enabled": True, "engine_id": "athena-1", "state": "paused"}

    monkeypatch.setattr(cyberengine_client.CyberEngineClient, "from_settings",
                        classmethod(lambda cls: _Stub()))
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.get("/api/failsafe/state/")
    assert r.status_code == 200
    assert r.data["engine_state"] == "paused"
    assert r.data["engine_state_available"] is True


def test_state_reports_not_available_when_the_engine_cannot_be_reached(monkeypatch):
    from ai_engine.services import cyberengine_client

    def _boom(cls):
        raise cyberengine_client.EngineError(
            "engine unreachable", kind=cyberengine_client.ENGINE_UNREACHABLE
        )

    monkeypatch.setattr(cyberengine_client.CyberEngineClient, "from_settings", classmethod(_boom))
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.get("/api/failsafe/state/")
    # The engine being down must not 500 the control plane's own view.
    assert r.status_code == 200
    assert r.data["engine_state"] is None
    assert r.data["engine_state_available"] is False


def test_state_treats_a_disabled_engine_failsafe_as_not_reported(monkeypatch):
    from ai_engine.services import cyberengine_client

    class _Stub:
        def failsafe_state(self):
            return {"enabled": False, "engine_id": None, "state": None}

    monkeypatch.setattr(cyberengine_client.CyberEngineClient, "from_settings",
                        classmethod(lambda cls: _Stub()))
    analyst = _client(_user(User.Roles.ANALYST))
    r = analyst.get("/api/failsafe/state/")
    assert r.data["engine_state"] is None
    assert r.data["engine_state_available"] is False


# ---------------------------------------------------------------------------
# One key is one person, whatever it is enrolled as
# ---------------------------------------------------------------------------

def test_one_key_enrolled_twice_is_still_one_person(settings):
    """The console and the engine must count the same thing.

    The engine (`mythos_core.failsafe.commands.verify_command`) counts distinct
    public key *material*. The console counted distinct `key_id`. So one private
    key enrolled under two ids -- which is what happens when an operator's
    hardware token is re-enrolled, or when one line of FAILSAFE_OPERATOR_KEYS is
    copy-pasted -- satisfied the console's threshold of two and was refused by
    the engine.

    The engine fails safe, so nothing was ever wrongly stood down. What this
    test is really about is the silence: the console published the command as
    READY, the engine rejected it, the rejection lived only in the governor's
    in-memory history which no route exposes, and an operator read "stand-down
    ready" beside a scan that never stopped.
    """
    settings.FAILSAFE_OPERATOR_KEYS = {
        "alice": ALICE_PUB,
        "alice-yubikey": ALICE_PUB,  # the same key, a second id
        "bob": BOB_PUB,
    }
    admin = _client(_user(User.Roles.ADMIN))
    r = admin.post("/api/failsafe/commands/",
                   {"action": "stand_down", "engine_id": "athena-1"}, format="json")
    uuid, fields = r.data["uuid"], _draft_fields(r.data)

    admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
               sign_draft(fields, key_id="alice", private_hex=ALICE_PRIV), format="json")
    second = admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
                        sign_draft(fields, key_id="alice-yubikey", private_hex=ALICE_PRIV),
                        format="json")

    assert second.status_code == 200
    assert second.data["status"] == "awaiting_signatures", (
        "one key under two ids was counted as two people, and the engine would "
        "have refused the command the console published as ready"
    )


def test_two_genuinely_different_keys_still_reach_ready(settings):
    """The guard must not be a two-person rule nobody can satisfy."""
    settings.FAILSAFE_OPERATOR_KEYS = {
        "alice": ALICE_PUB,
        "alice-yubikey": ALICE_PUB,
        "bob": BOB_PUB,
    }
    admin = _client(_user(User.Roles.ADMIN))
    r = admin.post("/api/failsafe/commands/",
                   {"action": "stand_down", "engine_id": "athena-1"}, format="json")
    uuid, fields = r.data["uuid"], _draft_fields(r.data)

    admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
               sign_draft(fields, key_id="alice", private_hex=ALICE_PRIV), format="json")
    bob = admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
                     sign_draft(fields, key_id="bob", private_hex=BOB_PRIV), format="json")

    assert bob.data["status"] == "ready"


def test_the_console_and_the_engine_agree_on_the_same_signature_set(settings):
    """Asserted against the engine's own verifier rather than against a number.

    A threshold check that agrees with a hard-coded 2 is not the property that
    matters. The property is that the console never publishes a command the
    engine will refuse, so this asks the engine.
    """
    from mythos_core.failsafe.commands import Command, verify_command

    settings.FAILSAFE_OPERATOR_KEYS = {"alice": ALICE_PUB, "alice-2": ALICE_PUB}
    admin = _client(_user(User.Roles.ADMIN))
    r = admin.post("/api/failsafe/commands/",
                   {"action": "stand_down", "engine_id": "athena-1"}, format="json")
    uuid, fields = r.data["uuid"], _draft_fields(r.data)
    for key_id in ("alice", "alice-2"):
        admin.post(f"/api/failsafe/commands/{uuid}/signatures/",
                   sign_draft(fields, key_id=key_id, private_hex=ALICE_PRIV), format="json")

    detail = admin.get(f"/api/failsafe/commands/{uuid}/").data
    console_says_ready = detail["status"] == "ready"

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ring = {
        "alice": Ed25519PublicKey.from_public_bytes(bytes.fromhex(ALICE_PUB)),
        "alice-2": Ed25519PublicKey.from_public_bytes(bytes.fromhex(ALICE_PUB)),
    }
    pending = admin.get("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    published = [c for c in (pending.data or {}).get("commands", [])
                 if c.get("nonce") == fields["nonce"]]

    if console_says_ready:
        assert published, "the console said ready but published nothing"
        accepted = verify_command(Command.from_dict(published[0]), keyring=ring,
                                  engine_id="athena-1")
        assert accepted, (
            "the console published a command the engine refuses -- the two sides "
            "are counting different things again"
        )
    else:
        assert not published
