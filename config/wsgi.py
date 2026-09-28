"""
WSGI config for config project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

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
