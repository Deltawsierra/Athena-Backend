"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_asgi_application()

# A serving process retries the blocking-decision dispatches still owed -- ones a
# process left behind when it exited, or whose runs all failed -- a few seconds
# after start and then every ASSURANCE_DISPATCH_SWEEP_SECONDS, on a daemon thread
# that never blocks startup or any request (#303).
from assurance.dispatch import start_owed_sweeper  # noqa: E402

start_owed_sweeper()
