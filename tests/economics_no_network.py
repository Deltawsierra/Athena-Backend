"""A pytest plugin, loaded only with ``-p tests.economics_no_network`` by
``tests/test_economics_feeds.py::test_importing_the_feed_modules_reaches_no_host``.

It makes every socket refuse to connect and every name lookup refuse to resolve --
loopback included -- before pytest-django loads Django, and lists each attempt in
:data:`TRIED`. ``tests/economics_no_network_cases.py`` then imports the feed modules,
the data-health route and the fetch command, and resolves the route: nothing may try
the network at import. Django is loaded by pytest, through the repository's own
pytest.ini, as for every test. Its name does not match ``test_*.py``, so the suite
never collects it.
"""

from __future__ import annotations

import socket

TRIED: list[str] = []


def _refuse(*args, **_kwargs):
    TRIED.append(repr(args[:2]))
    raise OSError("no network at import")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.getaddrinfo = _refuse
socket.create_connection = _refuse
