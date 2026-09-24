"""Request parsers the API uses in place of DRF's own."""

from __future__ import annotations

from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser


class SafeJSONParser(JSONParser):
    """DRF's JSON parser, with a body nested past the interpreter's stack answered
    as the malformed request it is.

    ``json.load`` raises ``RecursionError`` on a body of a few thousand opening
    brackets, and DRF's parser catches only ``ValueError``. That reached every
    JSON route as a 500 from a request anyone authenticated could send, with a
    stack trace in the log for each one. A body nobody could have meant is a 400.
    """

    def parse(self, stream, media_type=None, parser_context=None):
        try:
            return super().parse(stream, media_type, parser_context)
        except RecursionError:
            raise ParseError("JSON parse error - the body is nested too deeply") from None
