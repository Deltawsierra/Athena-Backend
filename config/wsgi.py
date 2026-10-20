"""
WSGI config for config project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import gc
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

_application = get_wsgi_application()

# The sweeper of owed blocking-decision dispatches (#303) is started by the process
# that SERVES, on its first request -- never here, at import: under a pre-forking
# server that imports this module in its master (gunicorn --preload), a thread
# started here would run in the master and not in the workers it forks.
from assurance import dispatch as _dispatch  # noqa: E402


def application(environ, start_response):
    _dispatch.ensure_owed_sweeper()
    return _application(environ, start_response)


#: Set once the start-up heap has been frozen, so a repeat import or a repeat
#: call is a no-op. :func:`gc.freeze` is one-way per worker; this guards it.
_frozen = False


def _freeze_startup_heap():
    """Freeze the long-lived start-up objects out of the collector's reach, once.

    Everything ``get_wsgi_application()`` built above -- Django's app registry,
    the URLconf, DRF, the compiled regexes -- lives for the worker's whole life,
    yet a full (generation-2) collection walks all of it every time one runs.
    :func:`gc.freeze` moves what is tracked now into the permanent generation the
    collector never walks, so full collections are cheaper and rarer: the #176
    follow-up, so a full collection in another thread can no longer hold the GIL
    through a stop. It does NOT disable the collector and does not touch the #176
    hold in ``safety.collection``.

    Called at import -- worker start-up -- and never on a request or a stop path.
    Under a pre-forking server that imports this module in its master
    (gunicorn --preload) the freeze runs there before the workers are forked, and
    each worker inherits the frozen generation; without --preload each worker
    imports this module and freezes its own. Either way every served worker runs
    with its start-up heap frozen. Idempotent: a second call does nothing.
    """
    global _frozen
    if _frozen:
        return
    _frozen = True
    gc.freeze()


_freeze_startup_heap()
