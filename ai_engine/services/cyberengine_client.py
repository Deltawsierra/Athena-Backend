import time

import requests
from django.conf import settings as django_settings
from django.conf import settings


# (connect, read). Overridable so a long scan can be given more room without
# editing source.
ENGINE_TIMEOUT = (
    float(getattr(django_settings, "CYBERENGINE_CONNECT_TIMEOUT", 3.05)),
    float(getattr(django_settings, "CYBERENGINE_READ_TIMEOUT", 60)),
)


# How long to keep collecting a scan the engine is running for us, and how
# often to ask. Polling does not hold a connection, so this can be far longer
# than any read timeout: a scan that takes four minutes is now four minutes of
# waiting rather than a scan the engine ran and we recorded nothing about.
SCAN_COLLECT_SECONDS = float(getattr(django_settings, "CYBERENGINE_SCAN_TIMEOUT", 600))
SCAN_POLL_SECONDS = float(getattr(django_settings, "CYBERENGINE_POLL_INTERVAL", 2.0))

# Handed to the engine so a short scan answers on the first request and needs
# no polling at all. Comfortably inside the read timeout.
SCAN_INLINE_WAIT_SECONDS = 20.0


# How much of a bad response body goes into an exception message. The engine's
# body is not bounded by anything this process controls -- a proxy in front of
# it answers with its own error page, which can be large -- and an exception
# message becomes a log line, a traceback, and an API error field.
MAX_BODY_EXCERPT = 500


def _excerpt(text: str) -> str:
    """The head of a response body, with the full size named rather than lost."""
    if len(text) <= MAX_BODY_EXCERPT:
        return text
    return f"{text[:MAX_BODY_EXCERPT]}... ({len(text)} characters total)"


class EngineError(Exception):
    pass


class ScanStillRunning(EngineError):
    """
    We stopped collecting before the engine finished.

    Carries the run id, because the scan is still going and its result can be
    collected later. Losing that id is how a scan becomes work the engine did
    for a customer that nobody has a record of.
    """

    def __init__(self, message: str, run_id: str):
        super().__init__(message)
        self.run_id = run_id


class CyberEngineClient:
    """
    Thin HTTP client for the external Cybersecurity AI Engine.
    Django contains NO AI logic.
    """

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }

    @classmethod
    def from_settings(cls):
        if not settings.CYBERENGINE_OPERATOR_KEY:
            raise RuntimeError("CYBERENGINE_OPERATOR_KEY is not configured")

        if not settings.CYBERENGINE_URL:
            raise RuntimeError("CYBERENGINE_URL is not configured")

        return cls(
            base_url=settings.CYBERENGINE_URL,
            api_key=settings.CYBERENGINE_OPERATOR_KEY,
        )

    def _read_json(self, resp: requests.Response, path: str) -> dict:
        """
        The body of a successful engine response, as the object it must be.

        This exists because resp.json() used to be called outside the try
        blocks below. EngineError is this client's whole contract with the
        nine places that handle an engine which cannot answer -- the two
        views modules, preflight, and the approve_deployment command -- and
        a 2xx response whose body is not JSON raised JSONDecodeError straight
        past all of them. An engine fronted by a proxy that answers 200 with
        an HTML holding page, or a write truncated mid-object, read as a bug
        in this process rather than as a bad answer from the engine.

        A body that decodes to something other than an object is the same
        failure one step later: every caller and this file's own annotations
        say dict, so a JSON null or list travels as far as the first .get()
        and surfaces as an AttributeError with no mention of the engine.
        """
        try:
            body = resp.json()
        except ValueError as exc:
            raise EngineError(
                f"Engine returned a body that is not JSON from {path} "
                f"(status {resp.status_code}): {_excerpt(resp.text)}"
            ) from exc

        if not isinstance(body, dict):
            raise EngineError(
                f"Engine returned {type(body).__name__}, not an object, from "
                f"{path} (status {resp.status_code}): {_excerpt(resp.text)}"
            )

        return body

    def _get(self, path: str) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}{path}", headers=self.headers, timeout=ENGINE_TIMEOUT
            )
        except requests.RequestException as e:
            raise EngineError(f"Engine unreachable: {e}") from e

        if not (200 <= resp.status_code < 300):
            raise EngineError(f"Engine error {resp.status_code}: {_excerpt(resp.text)}")

        return self._read_json(resp, path)

    def _post(self, path: str, payload: dict) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=self.headers,
                # A connect and read pair. This was a single value of 1000 seconds,
                # commented as preventing worker starvation, which is what it
                # caused: one hung engine call pinned a worker for 17 minutes.
                timeout=ENGINE_TIMEOUT,
            )
        except requests.RequestException as e:
            raise EngineError(f"Engine unreachable: {e}") from e

        if not (200 <= resp.status_code < 300):
            raise EngineError(
                f"Engine error {resp.status_code}: {_excerpt(resp.text)}"
            )

        return self._read_json(resp, path)

    # --------------------------------------------------
    # ENGINE ENDPOINTS
    # --------------------------------------------------

    def sign_assurance_receipt(self, receipt: dict) -> dict:
        """Ask the engine to sign an assurance receipt, returning a DSSE envelope.

        The engine holds the keys and this backend does not -- `assurance.receipt`
        has said so since it was written, and this is the call that makes the
        sentence true rather than an explanation of an absence.

        What comes back is an envelope whose signature is bound to the document
        kind, so it cannot be re-presented as an evidence pack. Verification is the
        auditor's job and is done offline against the engine's published keyring;
        this client does not verify, and a caller must not read the envelope's
        payload as though it had.

        Raises EngineError like every other call here, including when the engine
        has no key -- it answers 503 and says which. The caller's job is to report
        the receipt as UNSIGNED with that reason, never to drop the reason and
        serve a bare receipt that looks like a deliberate choice.
        """
        return self._post("/api/assurance/receipt/sign", {"receipt": receipt})

    def assurance_keyring(self) -> dict:
        """The engine's published public keyring, for an auditor verifying offline.

        Proxied so an operator reading a signed receipt here can reach the keys
        without a second credential. It remains true that a keyring fetched
        alongside the artifact it checks proves less than one fetched out of band,
        and the engine's own response says so in its `caveat`; this passes that
        through rather than stripping it.
        """
        return self._get("/api/assurance/keyring")

    def run_scan(self, target: str, engagement_ref: str | None = None) -> dict:
        """
        Run a scan and return its findings.

        The engine runs a scan as a job now. It used to run inside this
        request, and a measured scan of a target answering in 0.4 seconds took
        eighty-one against a sixty second read timeout — so the ordinary case
        was that the engine tested a customer's live system and we recorded
        "engine unreachable". We submit, and then collect.
        """
        payload = {"target": target, "wait_seconds": SCAN_INLINE_WAIT_SECONDS}
        if engagement_ref:
            payload["engagement_ref"] = engagement_ref

        accepted = self._post("/api/scan", payload)

        # A short scan comes back finished on the first request.
        if accepted.get("done") and accepted.get("result") is not None:
            return accepted["result"]
        if "run_id" not in accepted:
            # An older engine that still answers synchronously.
            return accepted

        return self.collect_scan(accepted["run_id"])

    def collect_scan(self, run_id: str) -> dict:
        """
        Wait for a scan the engine is running, and return its findings.

        Raises ScanStillRunning, carrying the id, if we give up first: the
        scan is still going, and the caller needs the id to record that and
        collect it later.
        """
        deadline = time.monotonic() + SCAN_COLLECT_SECONDS

        while True:
            status = self._get(f"/api/scans/{run_id}")

            if status.get("done"):
                if status.get("state") == "completed":
                    return status.get("result") or {}
                raise EngineError(
                    f"Scan {status.get('state')}: "
                    f"{status.get('reason') or (status.get('result') or {}).get('error') or 'no reason given'}"
                )

            if time.monotonic() >= deadline:
                raise ScanStillRunning(
                    f"The engine is still running this scan after "
                    f"{SCAN_COLLECT_SECONDS:.0f}s; it can be collected later.",
                    run_id=run_id,
                )

            time.sleep(SCAN_POLL_SECONDS)

    def run_llm_scan(self, payload: dict) -> dict:
        """
        Run an LLM Target Red Team scan (multi-turn).
        Payload example:
          {
            "target_name": "Client LLM",
            "adapter": "openai_style",
            "base_url": "https://client-proxy/v1/chat/completions",
            "model": "gpt-4.1-mini",
            "attacks": ["metaprompt_extraction","direct_prompt_injection","crescendosafe"],
            "max_turns": 8
          }
        """
        return self._post("/api/llm-scan", payload)

    def classify_cve(self, text: str) -> dict:
        return self._post("/api/classify-cve", {"text": text})

    def defend_log_text(self, text: str) -> dict:
        """
        Send raw log text to the engine defender for analysis.
        """
        return self._post("/api/defend-log/text", {"text": text})

    def defend_log_file(self, file_bytes: bytes, filename: str) -> dict:
        """
        Send a log file to the engine defender for analysis.
        """
        files = {
            "file": (filename, file_bytes),
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/defend-log/file",
                headers={"X-API-Key": self.headers["X-API-Key"]},
                files=files,
                timeout=30,
            )
        except requests.RequestException as e:
            raise EngineError(f"Engine unreachable: {e}") from e

        if not (200 <= resp.status_code < 300):
            raise EngineError(
                f"Engine error {resp.status_code}: {_excerpt(resp.text)}"
            )

        return self._read_json(resp, "/api/defend-log/file")

    # --------------------------------------------------
    # GOVERNANCE
    #
    # Six subsystems the engine grew -- the assurance tuple and change gate,
    # the authorization-to-effect ledger, the extension lifecycle gate, the
    # decision twin and remediation replay, route attestation, and the
    # incident evidence pack -- had no caller here at all. A grep of this
    # repository for "assurance", "/api/extensions", "/api/authority" and
    # "/api/evidence" returned nothing, so the change gate was consulted only
    # by its own HTTP route and its own tests. extensions/gate.py names the
    # realistic failure as "the engine ran for a week with a changed scanner
    # and nobody read the endpoint"; that was not a risk, it was the shipped
    # configuration.
    # --------------------------------------------------

    def assurance_check(self, deployment_id: str, components: dict,
                        tenant_id: str | None = None) -> dict:
        """Is the engine that is running still the one that was approved?

        Answers 200 with a verdict rather than a status code, so read
        `verdict`, not the HTTP result. The engine adds the measured half --
        the extension inventory, the egress allowlist as actually configured,
        and whether the other controls are switched on -- from its own
        process; it cannot be sent from here, which is the point.
        """
        payload = {"deployment_id": deployment_id, "components": components}
        if tenant_id:
            payload["tenant_id"] = tenant_id
        return self._post("/api/assurance/check", payload)

    def assurance_approve(self, deployment_id: str, components: dict,
                          approved_by: str | None = None, note: str | None = None,
                          tenant_id: str | None = None) -> dict:
        """Record what this deployment looks like at the moment it is approved."""
        payload = {"deployment_id": deployment_id, "components": components}
        if approved_by:
            payload["approved_by"] = approved_by
        if note:
            payload["note"] = note
        if tenant_id:
            payload["tenant_id"] = tenant_id
        return self._post("/api/assurance/approvals", payload)

    def assurance_measured(self) -> dict:
        """What the engine measures about itself, right now."""
        return self._get("/api/assurance/measured")

    def extension_review(self) -> dict:
        """Whether every loaded extension is the one that was approved."""
        return self._get("/api/extensions")

    def failsafe_state(self) -> dict:
        """The engine's live failsafe (governor) state, read from the engine
        itself: {enabled, engine_id, state}, where state is running / paused /
        stood_down / terminated, or null when the failsafe is disabled there.
        The control plane surfaces this so the operator console shows what the
        engine is actually doing rather than what was last commanded."""
        return self._get("/api/failsafe/state")

    def unattributed_effects(self, limit: int = 100) -> dict:
        """Effects the engine caused with no authority in force.

        The audit query. Anything in it names a code path that reached the
        network without one.
        """
        return self._get(f"/api/authority/unattributed?limit={limit}")

    def attestation_check(self, name: str, url: str, tenant_id: str | None = None) -> dict:
        """Measure a route now and compare it against its baseline."""
        payload = {"name": name, "url": url}
        if tenant_id:
            payload["tenant_id"] = tenant_id
        return self._post("/api/attestation/check", payload)

    def retest_finding(self, twin_id: int, engagement_ref: str,
                       scope: list | None = None, tenant_id: str | None = None) -> dict:
        """Is a finding still there?

        `engagement_ref` is required by the engine: a retest reaches the
        customer's system, and the authority for that has to be named now
        rather than inherited from the decision being retested.
        """
        payload = {"twin_id": twin_id, "engagement_ref": engagement_ref}
        if scope:
            payload["scope"] = scope
        if tenant_id:
            payload["tenant_id"] = tenant_id
        return self._post("/api/remediation/retest", payload)

    def evidence_pack(self, reason: str, since: str | None = None, until: str | None = None,
                      run_id: str | None = None, engagement_ref: str | None = None,
                      target: str | None = None, tenant_id: str | None = None,
                      only_run: str | None = None) -> dict:
        """Assemble a signed incident evidence pack.

        `since` and `until` must be ISO 8601 instants. The engine refuses a
        bound it cannot read rather than silently treating it as no bound,
        which would produce a pack claiming a narrow window over everything
        the tenant ever produced.
        """
        payload = {"reason": reason}
        for key, value in (("since", since), ("until", until), ("run_id", run_id),
                           ("engagement_ref", engagement_ref), ("target", target),
                           ("tenant_id", tenant_id), ("only_run", only_run)):
            if value:
                payload[key] = value
        return self._post("/api/evidence/pack", payload)
