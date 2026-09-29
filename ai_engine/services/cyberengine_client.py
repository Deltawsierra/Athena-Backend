import re
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


#: What KIND of engine failure this was, as a stable token rather than a sentence.
#:
#: The message is for a log. It carries the engine's own words -- its host and port
#: from ``requests``, up to ``MAX_BODY_EXCERPT`` of whatever body it answered with --
#: and this file's own comment above already says where such a message ends up: "a
#: log line, a traceback, and an API error field". The last of those is the problem.
#: ``assurance`` serves an unsigned receipt whose ``reason`` was ``str(exc)``, so a
#: deployment whose engine was unreachable published, to every authenticated reader:
#:
#:     Engine unreachable: HTTPConnectionPool(host='cyberengine.internal', port=8443)
#:     ... Failed to resolve 'cyberengine.internal'
#:
#: and a 500 from the engine published up to 500 characters of its traceback --
#: source paths, a key path, an upstream address. None of that is the reader's
#: business and none of it was ever on the signed route.
#:
#: So a caller that must TELL a reader what happened reads these instead. They carry
#: no text the engine chose.
ENGINE_UNREACHABLE = "unreachable"
ENGINE_REFUSED = "refused"
ENGINE_UNREADABLE = "unreadable"
ENGINE_RUN_FAILED = "run_failed"
ENGINE_STILL_RUNNING = "still_running"

ENGINE_FAILURE_KINDS = (
    ENGINE_UNREACHABLE,
    ENGINE_REFUSED,
    ENGINE_UNREADABLE,
    ENGINE_RUN_FAILED,
    ENGINE_STILL_RUNNING,
)


class EngineError(Exception):
    """A call to the engine did not produce an answer this process can use.

    ``kind`` is one of :data:`ENGINE_FAILURE_KINDS` and ``status`` is the engine's
    HTTP status where there was one. Both are structured so a caller can describe
    the failure without quoting the message -- see the note above
    :data:`ENGINE_UNREACHABLE`.

    ``kind`` has no default. A default would be taken by every raise site nobody
    updated, and the value of the field is that it is always the right one: a caller
    branching on a kind that silently means "some other failure" is back to reading
    the message.

    ``run_id`` is the engine's run this failure is about, where the engine named
    one: the id ``POST /api/scans/{run_id}/abort`` stops. It is carried so that a
    caller recording the failure can never be the place the only handle on a
    run was dropped. None when the engine named no run -- or named one whose
    work, it said, never started (athena-engine #71's 500 ``state: "failed"``,
    and its 429): there is nothing to stop, and nothing is recorded.
    """

    def __init__(self, message: str, *, kind: str, status: int | None = None,
                 run_id: str | None = None) -> None:
        super().__init__(message)
        if kind not in ENGINE_FAILURE_KINDS:
            raise ValueError(f"unknown engine failure kind {kind!r}")
        self.kind = kind
        self.status = status
        self.run_id = run_id


class ScanStillRunning(EngineError):
    """
    We stopped collecting before the engine finished.

    Carries the run id, because the scan is still going and its result can be
    collected later. Losing that id is how a scan becomes work the engine did
    for a customer that nobody has a record of.
    """

    def __init__(self, message: str, run_id: str):
        super().__init__(message, kind=ENGINE_STILL_RUNNING, run_id=run_id)


class ScanUncollected(ScanStillRunning):
    """
    The engine took the scan, and then could not be read about it.

    A status read that failed -- the engine unreachable, or answering 5xx, which
    under athena-engine #71 is exactly what a registry answering "database is
    locked" produces -- says nothing about the run: it may still be scanning the
    customer. So it is read as a scan still running, with its run id, never as
    a failed scan with the id thrown away.
    """


def _run_id_of(value) -> str | None:
    """The id a run is named by, as text, or None when there is no usable one.

    A number is its digits: engine main names a retest's scan record by an
    integer, and a run id that is read as absent is a run nothing can name.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value
    return None


#: How deeply an engine answer may nest before it is unreadable. The engine's
#: answers nest a handful of levels; a body nested deeper is not one of them, and
#: parsed it raised RecursionError -- not a ValueError, so straight past every
#: reader here and out of the scan view as a 500 with the scan left pending and
#: its run id dropped (round 4, E1).
MAX_JSON_DEPTH = 64

_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def _nesting_depth(text: str) -> int:
    """How deeply ``text`` nests arrays and objects, strings ignored. Linear, and
    never recursive."""
    depth = deepest = 0
    for char in _JSON_STRING.sub("", text):
        if char in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
        elif char in "]}":
            depth -= 1
    return deepest


def _json_of(resp: requests.Response):
    """``resp``'s body as JSON, or ValueError when it cannot be read: not JSON, or
    nested past :data:`MAX_JSON_DEPTH` (checked before it is parsed, and a
    RecursionError from the parser is the same answer)."""
    text = resp.text
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise ValueError(f"the body nests deeper than {MAX_JSON_DEPTH} levels")
    try:
        return resp.json()
    except RecursionError as exc:
        raise ValueError("the body nests too deeply to be read") from exc


def _header_run_id(resp: requests.Response) -> str | None:
    """The run #71 names in ``X-Run-Id``. Read where the body cannot be: a proxy
    that replaced a 500's body with its own page keeps the engine's headers, and
    the header is then the only handle on a run that may be scanning the customer."""
    return _run_id_of((resp.headers or {}).get("X-Run-Id"))


#: The one field athena-engine #71 answers every launch with, saying which of
#: its two shapes this is. Engine main sends no such field. Which contract
#: answered is read from it and from nothing else -- never guessed from which
#: keys happen to be present -- and a value that is neither is a shape this
#: backend does not read.
ANSWER_FIELD = "answer"
ANSWER_STATUS = "status"
ANSWER_VERDICT = "verdict"

#: The states the engine's run registry ends a run in.
RUN_COMPLETED = "completed"
RUN_FAILED = "failed"
RUN_ABORTED = "aborted"
#: The states a run has ended in; any other state is a run not known to have ended.
_RUN_ENDS = (RUN_COMPLETED, RUN_FAILED, RUN_ABORTED)
#: The states of a run that may still be going: stoppable by its id.
_RUN_GOING = ("queued", "running", "aborting")


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
            body = _json_of(resp)
        except ValueError as exc:
            raise EngineError(
                f"Engine returned a body that is not JSON from {path} "
                f"(status {resp.status_code}): {_excerpt(resp.text)}",
                kind=ENGINE_UNREADABLE,
                status=resp.status_code,
            ) from exc

        if not isinstance(body, dict):
            raise EngineError(
                f"Engine returned {type(body).__name__}, not an object, from "
                f"{path} (status {resp.status_code}): {_excerpt(resp.text)}",
                kind=ENGINE_UNREADABLE,
                status=resp.status_code,
            )

        return body

    def _send_get(self, path: str) -> requests.Response:
        """The engine's answer to a GET, whatever its status; raises only when there was none."""
        try:
            return requests.get(
                f"{self.base_url}{path}", headers=self.headers, timeout=ENGINE_TIMEOUT
            )
        except requests.RequestException as e:
            raise EngineError(f"Engine unreachable: {e}", kind=ENGINE_UNREACHABLE) from e

    def _send_post(self, path: str, payload: dict) -> requests.Response:
        """The engine's answer to a POST, whatever its status; raises only when there was none."""
        try:
            return requests.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=self.headers,
                # A connect and read pair. This was a single value of 1000 seconds,
                # commented as preventing worker starvation, which is what it
                # caused: one hung engine call pinned a worker for 17 minutes.
                timeout=ENGINE_TIMEOUT,
            )
        except requests.RequestException as e:
            raise EngineError(f"Engine unreachable: {e}", kind=ENGINE_UNREACHABLE) from e

    @staticmethod
    def _refused(resp: requests.Response) -> EngineError:
        return EngineError(
            f"Engine error {resp.status_code}: {_excerpt(resp.text)}",
            kind=ENGINE_REFUSED,
            status=resp.status_code,
        )

    def _get(self, path: str) -> dict:
        resp = self._send_get(path)
        if not (200 <= resp.status_code < 300):
            raise self._refused(resp)
        return self._read_json(resp, path)

    def _post(self, path: str, payload: dict) -> dict:
        resp = self._send_post(path, payload)
        if not (200 <= resp.status_code < 300):
            raise self._refused(resp)
        return self._read_json(resp, path)

    @staticmethod
    def _status_answer(resp: requests.Response) -> dict | None:
        """A body that is athena-engine #71's ``answer: "status"`` object, or None.

        Read from a non-2xx answer, where #71 still names the run it registered.
        Anything else -- engine main's error bodies, a proxy's page -- is None,
        and the caller reads the answer as the refusal it always was.
        """
        try:
            body = _json_of(resp)
        except ValueError:
            return None
        if isinstance(body, dict) and body.get(ANSWER_FIELD) == ANSWER_STATUS:
            return body
        return None

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

        How the answer is read (athena-engine #71, and engine main before it;
        tests/test_every_launch_answer_is_read_by_its_answer_field.py replays
        both, as the real engine sent them):

        * Which contract answered is read from ``answer`` alone. #71 marks every
          scan answer ``answer: "status"``; main sends none. Any other value is
          a shape this backend does not read: nothing is read from it, and the
          run it names is carried on the error so it can still be stopped.
        * Only a 200 is the run's end. A 202 is never "done", whatever ``state``
          it names: the engine reads the state after it hands the run to its
          pool, so a scan that finished in between is answered 202
          ``state: "completed"`` with no result in it. It is collected from
          ``/api/scans/{run_id}`` like any other.
        * A finished run is read by its state. Only ``completed`` is findings; a
          run that ended ``aborted`` (stopped) or ``failed`` is that, and never a
          scan that completed with nothing found.
        * A 500 that is a status naming a run is the engine failing AFTER it
          registered that run. ``state: null``: its work started, it is
          scanning, stoppable by that id, and records its own end -- it is
          collected, and if it cannot be collected it is still running, with
          its id. ``state: "failed"``: its work never started; nothing was sent
          to the target and there is nothing to stop.
        * 503 (the launch was not admitted) and 429 (the pool was full) started
          nothing, and are the refusals they always were.
        """
        payload = {"target": target, "wait_seconds": SCAN_INLINE_WAIT_SECONDS}
        if engagement_ref:
            payload["engagement_ref"] = engagement_ref

        resp = self._send_post("/api/scan", payload)

        if resp.status_code == 500:
            named = self._status_answer(resp)
            run_id = _run_id_of(named.get("run_id")) if named else None
            if named is None and _header_run_id(resp) is not None:
                # A 500 whose body cannot be read -- a proxy replaced it with its own
                # page -- that still carries #71's X-Run-Id: a run was registered,
                # and whether its work started is unknown. Collected like a 500
                # whose state is null: read, it says how it ended; unreadable, it
                # is still running, with its id.
                return self.collect_scan(_header_run_id(resp))
            if run_id is not None:
                if named.get("state") == RUN_FAILED:
                    raise EngineError(
                        f"The engine failed before the scan's work started "
                        f"(run {run_id}): {named.get('error') or 'no error given'}. "
                        f"Nothing was sent to the target.",
                        kind=ENGINE_REFUSED,
                        status=resp.status_code,
                    )
                # Its work started: it is scanning the customer, and this id is
                # the only handle on it.
                return self.collect_scan(run_id)

        if not (200 <= resp.status_code < 300):
            raise self._refused(resp)

        try:
            accepted = self._read_json(resp, "/api/scan")
        except EngineError as exc:
            if _header_run_id(resp) is not None:
                # The engine took the scan and named its run, and the body saying
                # so cannot be read: not a failed scan -- it may be scanning now.
                raise self._unread(resp.status_code, _header_run_id(resp), str(exc)) from exc
            raise
        run_id = _run_id_of(accepted.get("run_id"))

        if ANSWER_FIELD in accepted and accepted[ANSWER_FIELD] != ANSWER_STATUS:
            said = f"HTTP {resp.status_code} with answer {accepted[ANSWER_FIELD]!r}"
            if run_id is not None:
                # It names a run: whatever else it is, that run may be scanning the
                # customer. Kept pending with its id -- recorded FAILED, the scan
                # read as over while the engine may still be running it.
                raise self._unread(resp.status_code, run_id, said)
            raise EngineError(
                f"The engine answered a shape this backend does not read: {said} to a scan "
                f"start. Nothing was read from it.",
                kind=ENGINE_UNREADABLE,
                status=resp.status_code,
            )

        if resp.status_code == 200:
            if accepted.get("done") is True:
                if ANSWER_FIELD not in accepted:
                    if "state" not in accepted and accepted.get("result") is not None:
                        # An engine older than the run registry: done, and its result.
                        return accepted["result"]
                elif accepted.get("state") not in _RUN_ENDS:
                    # A #71 status is read by its `answer`, and it says how the run
                    # ended in `state`. With no end state it says nothing about the
                    # run -- never an old engine's result, whatever it carries: a
                    # stopped scan whose `state` was lost read as COMPLETED, clean.
                    if run_id is not None:
                        raise self._unread(
                            resp.status_code, run_id, f"a finished status with no end state ({accepted.get('state')!r})"
                        )
                    raise EngineError(
                        "The engine answered a scan start with a finished status that names "
                        "neither its run nor how it ended. Nothing was read from it.",
                        kind=ENGINE_UNREADABLE,
                        status=resp.status_code,
                    )
                return self._finished_scan(accepted, run_id)
            if run_id is None:
                if ANSWER_FIELD in accepted:
                    raise EngineError(
                        "The engine answered a scan start with a status that names no "
                        "run, so there is nothing to collect. Nothing was read from it.",
                        kind=ENGINE_UNREADABLE,
                        status=resp.status_code,
                    )
                # An older engine that still answers synchronously.
                return accepted
            return self.collect_scan(run_id)

        # A 202 (or any other 2xx): the run is not over, whatever state it names.
        if run_id is None:
            raise EngineError(
                f"The engine accepted the scan (HTTP {resp.status_code}) without naming "
                f"a run, so there is nothing to collect. Nothing was read from it.",
                kind=ENGINE_UNREADABLE,
                status=resp.status_code,
            )
        return self.collect_scan(run_id)

    @staticmethod
    def _unread(http_status: int | None, run_id: str, said: str) -> "ScanUncollected":
        """An answer about run ``run_id`` that this backend cannot read: the run is
        read as still running, with its id -- never as a failed scan -- because the
        answer says nothing about whether it ended."""
        return ScanUncollected(
            f"The engine answered a shape this backend does not read ({said}) about scan run "
            f"{run_id}. Nothing was read from it: the scan may still be running, is stopped by "
            f"that id, and can be collected later.",
            run_id=run_id,
        )

    @classmethod
    def _finished_scan(cls, status: dict, run_id: str | None) -> dict:
        """The findings of a run that has ended, or the error that it ended some other way.

        Only ``completed`` is a result. A stopped scan's result is whatever it
        had when it stopped -- often nothing -- and reading it as findings would
        record a scan an operator stopped as one that completed and found
        nothing. A run said to be done with no end state this backend reads is not
        known to have ended: it is still running, with its id.
        """
        state = status.get("state")
        if state not in _RUN_ENDS and run_id is not None:
            raise cls._unread(None, run_id, f"done, with state {state!r}")
        if state == RUN_COMPLETED:
            return status.get("result") or {}
        result = status.get("result") if isinstance(status.get("result"), dict) else {}
        raise EngineError(
            f"Scan {state}: "
            f"{status.get('reason') or result.get('error') or 'no reason given'}",
            kind=ENGINE_RUN_FAILED,
            run_id=run_id,
        )

    def collect_scan(self, run_id: str) -> dict:
        """
        Wait for a scan the engine is running, and return its findings.

        Raises ScanStillRunning, carrying the id, if we give up first: the
        scan is still going, and the caller needs the id to record that and
        collect it later. Raises ScanUncollected -- a ScanStillRunning -- when
        the engine cannot be read about the run: that is not news that the run
        ended, and the id is kept all the same.
        """
        deadline = time.monotonic() + SCAN_COLLECT_SECONDS
        path = f"/api/scans/{run_id}"

        while True:
            resp = self._send_get_or_uncollected(path, run_id)

            if resp.status_code == 404:
                # The engine has no such run: definite, and nothing to stop.
                raise EngineError(
                    f"The engine has no scan run {run_id}.",
                    kind=ENGINE_REFUSED,
                    status=resp.status_code,
                    run_id=run_id,
                )
            if not (200 <= resp.status_code < 300):
                raise ScanUncollected(
                    f"The engine answered {resp.status_code} when asked about scan run "
                    f"{run_id}; the scan may still be running, and can be collected "
                    f"later: {_excerpt(resp.text)}",
                    run_id=run_id,
                )
            try:
                status = self._read_json(resp, path)
            except EngineError as exc:
                raise ScanUncollected(
                    f"The engine's answer about scan run {run_id} could not be read; the "
                    f"scan may still be running, and can be collected later: {exc}",
                    run_id=run_id,
                ) from exc

            if status.get("done") is True:
                return self._finished_scan(status, run_id)

            if time.monotonic() >= deadline:
                raise ScanStillRunning(
                    f"The engine is still running this scan after "
                    f"{SCAN_COLLECT_SECONDS:.0f}s; it can be collected later.",
                    run_id=run_id,
                )

            time.sleep(SCAN_POLL_SECONDS)

    def _send_get_or_uncollected(self, path: str, run_id: str) -> requests.Response:
        try:
            return self._send_get(path)
        except EngineError as exc:
            raise ScanUncollected(
                f"The engine could not be reached about scan run {run_id}; the scan may "
                f"still be running, and can be collected later: {exc}",
                run_id=run_id,
            ) from exc

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
            raise EngineError(f"Engine unreachable: {e}", kind=ENGINE_UNREACHABLE) from e

        if not (200 <= resp.status_code < 300):
            raise EngineError(
                f"Engine error {resp.status_code}: {_excerpt(resp.text)}",
                kind=ENGINE_REFUSED,
                status=resp.status_code,
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
        """Is a finding still there? The engine's answer, read -- see :func:`read_retest_answer`.

        `engagement_ref` is required by the engine: a retest reaches the
        customer's system, and the authority for that has to be named now
        rather than inherited from the decision being retested.

        No ``wait_seconds`` is sent: engine main refuses the field (422) before
        it starts anything, and athena-engine #71 then waits up to its own cap
        and answers 202 with the run's status past it, which is read as a run
        still going -- collect it with :meth:`retest_status`.
        """
        payload = {"twin_id": twin_id, "engagement_ref": engagement_ref}
        if scope:
            payload["scope"] = scope
        if tenant_id:
            payload["tenant_id"] = tenant_id
        resp = self._send_post("/api/remediation/retest", payload)
        return read_retest_answer(self, resp)

    def retest_status(self, run_id: str) -> dict:
        """Where a retest the engine answered 202 (or a 500 that named it) is now.

        Read from ``/api/scans/{run_id}``, the ``status_url`` #71 answers with,
        built here from the run id rather than followed. See
        :func:`read_retest_run`.
        """
        path = f"/api/scans/{run_id}"
        resp = self._send_get(path)
        if not (200 <= resp.status_code < 300):
            raise EngineError(
                f"The engine answered {resp.status_code} when asked about retest run "
                f"{run_id}: {_excerpt(resp.text)}",
                kind=ENGINE_REFUSED,
                status=resp.status_code,
                run_id=run_id,
            )
        return read_retest_run(self._read_json(resp, path), run_id)

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


# --------------------------------------------------
# READING A RETEST
#
# A retest is a full scan of the customer's target, and athena-engine #71 made
# it a run like any other: registered before anything is sent, stoppable by its
# `run_id`, and answered in exactly two shapes told apart by `answer`. Engine
# main answers a verdict synchronously, with no `answer`, and its `run_id` is the
# scan record id -- not an id any stop names. Both are read here, into one
# reading, so no caller ever reads a raw body and guesses:
#
#   {"answer": "verdict", "verdict", "detail", "check", "scan_record_id",
#    "run_id", "stop_id", "state", "stopped_after_recording", "body"}
#   {"answer": "status", "phase", "run_id", "stop_id", "state", "reason",
#    "error", "http_status", "body"}
#
# `stop_id` is set only while the run may still be going: it is what a Stop
# names. `phase` is one of RETEST_PHASES. A retest that was stopped after its
# check was filed is a verdict -- the check is on the engine's chain and true --
# with `stopped_after_recording` naming the stop; never "nothing was filed", and
# never a plain verdict either.
# --------------------------------------------------

#: The run may still be going: it is stoppable by `stop_id`, and collected with
#: `CyberEngineClient.retest_status`.
RETEST_RUNNING = "running"
#: Stopped before it filed anything: no verdict, no check.
RETEST_STOPPED = "stopped"
#: Failed. `started` says whether any of its work began.
RETEST_FAILED = "failed"
#: Refused before any work started (a full pool): nothing to stop.
RETEST_REFUSED = "refused"
#: Ended without a verdict, for a reason the engine did not name.
RETEST_ENDED = "ended_without_verdict"

RETEST_PHASES = (RETEST_RUNNING, RETEST_STOPPED, RETEST_FAILED, RETEST_REFUSED, RETEST_ENDED)


def _retest_verdict(body: dict, *, scan_record_id, run_id, stop_id, state,
                    stopped_after_recording) -> dict:
    return {
        "answer": ANSWER_VERDICT,
        "verdict": body.get("verdict"),
        "detail": body.get("detail"),
        "check": body.get("check") if isinstance(body.get("check"), dict) else None,
        "scan_record_id": _run_id_of(scan_record_id),
        "run_id": run_id,
        "stop_id": stop_id,
        "state": state,
        "stopped_after_recording": stopped_after_recording,
        "body": body,
    }


def _retest_status(phase: str, *, run_id, state, reason=None, error=None,
                   http_status=None, body=None, started=True) -> dict:
    return {
        "answer": ANSWER_STATUS,
        "phase": phase,
        "run_id": run_id,
        # Only a run that may still be going has anything for a Stop to name.
        "stop_id": run_id if phase == RETEST_RUNNING else None,
        "state": state,
        "reason": reason,
        "error": error,
        "http_status": http_status,
        "started": started,
        "body": body,
    }


def _status_phase(state, *, http_status: int) -> str:
    """The phase an `answer: "status"` body is in. A 202 is always running."""
    if http_status == 202:
        return RETEST_RUNNING
    if state == RUN_ABORTED:
        return RETEST_STOPPED
    if state == RUN_FAILED:
        return RETEST_FAILED
    if state in ("queued", "running", "aborting"):
        return RETEST_RUNNING
    return RETEST_ENDED


def read_retest_answer(client: CyberEngineClient, resp: requests.Response) -> dict:
    """The engine's answer to ``POST /api/remediation/retest``, read by its ``answer``."""
    path = "/api/remediation/retest"
    status = resp.status_code

    if status in (429, 500):
        named = client._status_answer(resp)
        run_id = _run_id_of(named.get("run_id")) if named else None
        if status == 500 and named is None and _header_run_id(resp) is not None:
            # A 500 whose body a proxy replaced, still carrying #71's X-Run-Id: a run
            # was registered, and whether its work started is unknown -- running,
            # stoppable by that id, until it is read.
            return _retest_status(RETEST_RUNNING, run_id=_header_run_id(resp), state=None,
                                  error="the engine's answer could not be read", http_status=status,
                                  body=None)
        if run_id is not None:
            state = named.get("state")
            if status == 429:
                # The pool was full: the run was recorded FAILED and never started.
                return _retest_status(RETEST_REFUSED, run_id=None, state=state,
                                      error=named.get("error"), http_status=status,
                                      body=named, started=False)
            if state == RUN_FAILED:
                # Failed after it was registered, before its work started.
                return _retest_status(RETEST_FAILED, run_id=None, state=state,
                                      error=named.get("error"), http_status=status,
                                      body=named, started=False)
            # Failed after its work started: it is running, stoppable by this id.
            return _retest_status(RETEST_RUNNING, run_id=run_id, state=state,
                                  error=named.get("error"), http_status=status, body=named)

    if not (200 <= status < 300):
        # 503 (not admitted), 4xx, a bare 5xx: nothing this answer says started.
        raise client._refused(resp)

    try:
        body = client._read_json(resp, path)
    except EngineError:
        if _header_run_id(resp) is None:
            raise
        # The engine took the retest and named its run in X-Run-Id; the body saying
        # what it is cannot be read. It may still be running, and is stopped by that id.
        return _retest_status(RETEST_RUNNING, run_id=_header_run_id(resp), state=None,
                              error="the engine's answer could not be read", http_status=status,
                              body=None)
    named_run = _run_id_of(body.get("run_id"))

    if ANSWER_FIELD not in body:
        # Engine main: its verdict, synchronously, with the scan record id under
        # `run_id` and nothing a stop could name -- the retest is over. Neither
        # contract answers a 202, or a `scan_record_id`, without `answer`; read as
        # main's verdict either would be a check filed against an id that may be a
        # registry run, so neither is read.
        if status == 202 or "scan_record_id" in body or "verdict" not in body:
            raise EngineError(
                f"The engine answered a retest in a shape this backend does not read: "
                f"HTTP {status} with no `answer`. Nothing was read from it.",
                kind=ENGINE_UNREADABLE, status=status, run_id=None,
            )
        return _retest_verdict(body, scan_record_id=body.get("run_id"), run_id=None,
                               stop_id=None, state=None, stopped_after_recording=None)

    answer = body[ANSWER_FIELD]
    if status == 202 and answer != ANSWER_STATUS:
        raise EngineError(
            f"The engine answered a retest in a shape this backend does not read: HTTP 202 "
            f"with answer {answer!r}. A 202 is never a verdict; nothing was read from it.",
            kind=ENGINE_UNREADABLE, status=status, run_id=named_run,
        )
    if answer == ANSWER_VERDICT:
        state = body.get("state")
        stopped = body.get("stopped_after_recording")
        if state in _RUN_GOING:
            # A verdict whose run still reads as going has not been stopped: it is
            # read on (stoppable by its run id), never marked stopped after
            # recording -- which said a stop had landed that nobody made.
            return _retest_verdict(body, scan_record_id=body.get("scan_record_id"),
                                   run_id=named_run, stop_id=named_run, state=state,
                                   stopped_after_recording=None)
        if state not in (None, RUN_COMPLETED) and not stopped:
            # A verdict on a run that did not complete is one filed before a stop
            # landed: #71 names the stop. Said, even if it did not.
            stopped = state
        return _retest_verdict(body, scan_record_id=body.get("scan_record_id"),
                               run_id=named_run, stop_id=None, state=state,
                               stopped_after_recording=stopped or None)
    if answer == ANSWER_STATUS:
        phase = _status_phase(body.get("state"), http_status=status)
        if phase == RETEST_RUNNING and named_run is None:
            # Running, by its own account, and naming no run: nothing can collect it,
            # and nothing here can stop it. Refused as a scan start naming no run is,
            # and the missing stop handle is said.
            raise EngineError(
                f"The engine answered a retest HTTP {status} as running without naming its run, "
                "so there is nothing to collect -- and no stop handle: nothing here can stop it. "
                "Nothing was read from it.",
                kind=ENGINE_UNREADABLE, status=status, run_id=None,
            )
        return _retest_status(phase,
                              run_id=named_run, state=body.get("state"),
                              reason=body.get("reason"), error=body.get("error"),
                              http_status=status, body=body)
    raise EngineError(
        f"The engine answered a retest in a shape this backend does not read: answer "
        f"{answer!r} is neither a verdict nor a status. Nothing was read from it.",
        kind=ENGINE_UNREADABLE, status=status, run_id=named_run,
    )


def read_retest_run(status: dict, run_id: str) -> dict:
    """A retest run's ``/api/scans/{run_id}`` record, read.

    A verdict only by the rule the engine answers a waiting caller by: the run
    COMPLETED and its stored result carries one, or it was ABORTED after its
    check was filed (the result carries the verdict AND that check). A stopped
    run's stored ``{stopped, scan_incomplete}`` has no verdict and no check: it
    is a stop, and nothing was filed. A failed run keeps the runner's
    inconclusive verdict as its result, which is not a verdict on the finding.
    """
    state = status.get("state")
    result = status.get("result") if isinstance(status.get("result"), dict) else None
    done = status.get("done") is True
    has_verdict = result is not None and isinstance(result.get("verdict"), str)
    filed = has_verdict and isinstance(result.get("check"), dict)

    if done and state == RUN_COMPLETED and has_verdict:
        return _retest_verdict(result, scan_record_id=result.get("scan_record_id"),
                               run_id=run_id, stop_id=None, state=state,
                               stopped_after_recording=None)
    if done and state == RUN_ABORTED and filed:
        return _retest_verdict(result, scan_record_id=result.get("scan_record_id"),
                               run_id=run_id, stop_id=None, state=state,
                               stopped_after_recording=status.get("reason") or state)
    if not done:
        return _retest_status(RETEST_RUNNING, run_id=run_id, state=state,
                              reason=status.get("reason"), body=status)
    error = None
    if state == RUN_FAILED:
        error = (result or {}).get("error") or (result or {}).get("detail") or status.get("reason")
    phase = {RUN_ABORTED: RETEST_STOPPED, RUN_FAILED: RETEST_FAILED}.get(state, RETEST_ENDED)
    return _retest_status(phase, run_id=run_id, state=state, reason=status.get("reason"),
                          error=error, body=status)
