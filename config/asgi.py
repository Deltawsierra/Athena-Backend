"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

_application = get_asgi_application()

# The sweeper of owed blocking-decision dispatches (#303) is started by the process
# that SERVES, on its first request -- never here, at import (see config/wsgi.py).
from assurance import dispatch as _dispatch  # noqa: E402


async def application(scope, receive, send):
    _dispatch.ensure_owed_sweeper()
    return await _application(scope, receive, send)
