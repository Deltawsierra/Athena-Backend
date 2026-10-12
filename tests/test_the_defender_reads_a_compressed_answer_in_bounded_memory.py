"""The defender gateway reads a compressed engine answer in bounded memory.

The gateway (``audit.middleware.DefenderMiddleware``) reads the engine's answer
through urllib3's streaming API, ``response.raw.read1(_ANSWER_CHUNK,
decode_content=True)``, and stops at ``_ANSWER_LIMIT`` bytes. That bound is what
keeps an answer from costing the request more than 64 KiB -- and below urllib3
2.6.0 it did not hold for a compressed answer: the streaming API decoded a small
amount of highly compressed data whole in a single operation (GHSA-2xpw-w6gg-jr37),
and parts of it again until 2.7.0 (GHSA-mf9v-mfxr-j63j). A gzip answer of a few
kilobytes that inflates to 32 MiB cost the read about 10 MB at urllib3 2.5.0, the
version requirements.txt pinned, against about 0.06 MB at 2.8.0; the read
returned 4 KiB at a time either way, so only the memory shows it.

Measured here, end to end, through the gateway's own call over a real socket.
"""

from __future__ import annotations

import gzip
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

#: Uncompressed, it is 512 times the gateway's limit.
INFLATED_BYTES = 32 * 1024 * 1024
#: Peak memory the read may allocate: generous for a 64 KiB bound, and far under
#: what a whole decode of one compressed read costs (about 10 MB at 2.5.0).
PEAK_BOUND_BYTES = 2 * 1024 * 1024


@pytest.fixture
def bomb_engine(monkeypatch):
    body = gzip.compress(b"\0" * INFLATED_BYTES, compresslevel=9)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    # The gateway stops reading at its limit and closes: a broken pipe, not news.
    server.handle_error = lambda *_args: None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost")
    yield f"http://127.0.0.1:{server.server_address[1]}", len(body)
    server.shutdown()
    server.server_close()


def test_a_compressed_answer_past_the_limit_is_refused_in_bounded_memory(bomb_engine):
    from django.http import HttpResponse
    from django.test import override_settings

    from audit import middleware

    base, compressed = bomb_engine
    assert compressed < middleware._ANSWER_LIMIT, "the answer must arrive under the limit, compressed"
    with override_settings(CYBERENGINE_URL=base, CYBERENGINE_OPERATOR_KEY="operator-key", DEFENDER_TIMEOUT_SECONDS=10):
        gateway = middleware.DefenderMiddleware(lambda request: HttpResponse("ok"))
        tracemalloc.start()
        try:
            decision, problem = gateway._call_engine({"path": "/api/x", "method": "GET"}, time.monotonic() + 10)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

    assert decision is None and "larger than" in (problem or ""), (decision, problem)
    assert peak < PEAK_BOUND_BYTES, f"the read allocated {peak} bytes at its peak"
