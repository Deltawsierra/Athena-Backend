"""The worker freezes its start-up heap, and nothing on a request or stop does.

#176 held the collector off while a stop is served, because a full
(generation-2) collection -- a pass over every tracked object in the process --
kept landing inside stops and eating the stop's latency budget. This is its
queued follow-up: once the worker is built, ``config.wsgi`` calls
:func:`gc.freeze`, which moves the long-lived start-up objects (Django's app
registry, the URLconf, DRF, the compiled regexes) into the permanent generation
the collector never walks. The set a full collection then walks is much smaller,
so full collections are cheaper and rarer, and one running in another thread can
no longer hold the GIL through a stop.

THE SAFETY RULE: the freeze is worker start-up work only -- never on a request,
a stop, a pause, a revoke or a signal handler -- and never sits on or delays a
stop. These tests pin that: importing the entry point freezes exactly once, a
second call is a no-op, serving a request never freezes, and no module on the
stop path calls :func:`gc.freeze` at all. The freeze does not disable the
collector and leaves the #176 hold (``safety.collection``) untouched.
"""

import gc
import importlib
import pathlib

from django.conf import settings

#: The request path that reaches a stop, as #176 built it: ``DefenderMiddleware``
#: judges a request a stop, which puts the ``safety.collection`` hold on the
#: collector, released when the response closes. A :func:`gc.freeze` anywhere on
#: this path would be a pass over the heap inside the stop -- the cost #176
#: removed -- so it must appear on none of them.
STOP_PATH_MODULES = (
    "audit/middleware.py",
    "safety/collection.py",
    "safety/stops.py",
)


def test_building_the_worker_freezes_the_startup_heap_once(monkeypatch):
    """Importing ``config.wsgi`` -- what a worker does as it starts -- freezes
    the heap exactly once. Reloading the module re-runs its top-level code (the
    start-up path) with :func:`gc.freeze` counted rather than run, so the real
    heap is not touched by the test."""
    from config import wsgi

    frozen = []
    monkeypatch.setattr(gc, "freeze", lambda: frozen.append(1))
    importlib.reload(wsgi)
    assert frozen == [1], frozen


def test_a_second_start_up_call_does_not_freeze_again(monkeypatch):
    """:func:`gc.freeze` is one-way per worker, so the guard makes a repeat call
    a no-op: a double import, or a belt-and-braces second call, freezes once."""
    from config import wsgi

    frozen = []
    monkeypatch.setattr(gc, "freeze", lambda: frozen.append(1))
    monkeypatch.setattr(wsgi, "_frozen", False)
    wsgi._freeze_startup_heap()
    wsgi._freeze_startup_heap()
    assert frozen == [1], frozen


def test_serving_a_request_never_freezes_the_heap(monkeypatch):
    """Serving a request through ``config.wsgi.application`` never freezes --
    even on a worker whose start-up freeze somehow did not run. The freeze is
    start-up work; a request must never carry it."""
    from config import wsgi

    frozen = []
    monkeypatch.setattr(gc, "freeze", lambda: frozen.append(1))
    monkeypatch.setattr(wsgi._dispatch, "ensure_owed_sweeper", lambda: None)
    monkeypatch.setattr(wsgi, "_application", lambda environ, start_response: ["ok"])
    monkeypatch.setattr(wsgi, "_frozen", False, raising=False)
    assert wsgi.application({}, lambda *args: None) == ["ok"]
    assert frozen == [], frozen


def test_no_module_on_the_stop_path_freezes_the_collector():
    """The freeze lives at the entry point and nowhere a stop can reach. Each
    stop-path module stays free of :func:`gc.freeze`, and the entry point is the
    one place that calls it."""
    root = pathlib.Path(settings.BASE_DIR)
    for name in STOP_PATH_MODULES:
        assert "gc.freeze" not in (root / name).read_text(encoding="utf-8"), name
    assert "gc.freeze()" in (root / "config" / "wsgi.py").read_text(encoding="utf-8")
