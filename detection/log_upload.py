"""A log file uploaded to ``POST /api/detection/defender/file/``, and log text posted to
``POST /api/detection/defender/text/``, each read within a bound.

The view took a bare ``serializers.FileField()`` and ran ``uploaded_file.read().decode()``:
no limit on size or kind, the whole file held in memory, then sent on to the engine's
defender. It now checks, in this order, and reads nothing until the last of the checks
that need no read has passed:

  1. The declared ``Content-Length``, before ``request.data`` is parsed: over
     ``LOG_UPLOAD_MAX_REQUEST_BYTES`` is refused 413 with nothing read.
  2. The type the file declares: one that is not a log's is 415.
  3. The file's size, as the parser counted it, against ``LOG_UPLOAD_MAX_BYTES``: 413.
  4. A bounded read, in chunks, that stops at one byte past the cap: 413. A size that
     was wrong or missing cannot make the read unbounded.
  5. The head of the file: a NUL byte in it is not text (a UTF-16 file has one every
     other byte, and this reads UTF-8): 415.

Every refusal is a fixed sentence. None quotes the file's content, its name or the type it
declared.

What this cannot do is stop Django receiving the body: Django parses a multipart body
before the view runs (above ``FILE_UPLOAD_MAX_MEMORY_SIZE`` it goes to a temporary file,
not to memory), and a declared length is refused before that parse only while the
client declares one. A server in front of this one that caps request bodies is the layer
that stops a body being received at all.

The figures are the engine's (``engine/utils/log_upload.py`` in Athena-Engine), which
refuses a file over its cap with a 413 of its own: this cap must never be larger.

The text view had the same defect: ``serializers.CharField()`` with no ``max_length``, so
only Django's request-body limit applied. It now checks, in this order:

  1. The declared ``Content-Length``, before ``request.data`` is parsed: over
     ``LOG_TEXT_MAX_REQUEST_BYTES`` is refused 413 with nothing read.
  2. The serializer's ``max_length``, ``LOG_UPLOAD_MAX_BYTES`` characters: a text over it is
     refused 413 (``refuse_invalid_text``), not the 400 a validation error is.
  3. The text's own size in UTF-8 bytes, ``check_log_text``: 413. A character is at least one
     byte, so this is the check that holds for text that is not ASCII.

The same fixed sentence as the file view's. Nothing here is on a stop's path.
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError

#: The most a log file uploaded to ``POST /api/detection/defender/file/`` may be, in
#: bytes: 1 MiB.
#:
#: Neither the engine's text route nor this backend's had a limit of its own, so there
#: was no figure to match; this one is the engine's file-upload cap, chosen from what the
#: defender costs. Measured on the engine, ``LogDefender.analyze_lines`` takes about 1 s
#: of CPU per MiB of ordinary access-log lines, and about 14 s per MiB of lines that all
#: alert, which also answers with about 37 MiB of JSON for that one MiB (and this
#: service stores that answer, whole, in ``ThreatDetection.engine_response``). 1 MiB is
#: some 8,500 ordinary lines.
#:
#: It must never exceed the engine's ``LOG_UPLOAD_MAX_BYTES``: this view sends the file
#: on as text, and a file the engine would refuse is a file this view should have.
LOG_UPLOAD_MAX_BYTES = 1024 * 1024

#: What the multipart framing around the file may add (boundary lines, the part's
#: headers, a few small fields). The file is held to ``LOG_UPLOAD_MAX_BYTES`` exactly;
#: this only keeps a file at the cap from being refused for the envelope it travels in.
LOG_UPLOAD_ENVELOPE_BYTES = 16 * 1024

#: The most the whole request body may declare.
LOG_UPLOAD_MAX_REQUEST_BYTES = LOG_UPLOAD_MAX_BYTES + LOG_UPLOAD_ENVELOPE_BYTES

#: The most JSON can make of one byte of text: a control character such as ``\x01`` is one
#: byte as text and six as ``\u0001``, which is how Python's ``json.dumps`` (and so
#: ``requests``' ``json=``) writes it. A newline is two, a character outside the Basic
#: Multilingual Plane three, the rest less. The engine's text route holds the same figure.
LOG_TEXT_JSON_EXPANSION = 6

#: The most the whole request body of ``POST /api/detection/defender/text/`` may declare: a
#: text at the cap in its worst JSON spelling, and the envelope around it. It is not a second
#: cap on the text, which is ``LOG_UPLOAD_MAX_BYTES``; it is the bound the declared length is
#: held to, so that no text the cap allows is refused for how its client wrote it down.
LOG_TEXT_MAX_REQUEST_BYTES = LOG_UPLOAD_MAX_BYTES * LOG_TEXT_JSON_EXPANSION + LOG_UPLOAD_ENVELOPE_BYTES

#: How much of the file is looked at to tell text from a binary: the head, as git does.
LOG_UPLOAD_SNIFF_BYTES = 8192

#: How much of the file is read at a time.
LOG_UPLOAD_READ_CHUNK_BYTES = 64 * 1024

#: The types a log file is sent as. A browser sends a ``.log`` file, or any extension it
#: has no type for, as ``application/octet-stream`` (the Investigations page's file
#: input has no ``accept``); ``requests`` does the same for a name it cannot guess. Any
#: ``text/*`` is accepted as well, and a file that declares no type. Anything else (an
#: image, a PDF, an archive) is not a log.
LOG_UPLOAD_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/json",
        "application/x-ndjson",
        "application/jsonl",
        "application/xml",
    }
)


class LogUploadTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = f"A log file is at most {LOG_UPLOAD_MAX_BYTES} bytes."
    default_code = "log_upload_too_large"


class LogUploadNotText(APIException):
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    default_detail = "The log file must be text (UTF-8); this one is not."
    default_code = "log_upload_not_text"


def is_log_type(content_type: str | None) -> bool:
    """Whether a file declaring ``content_type`` may be a log: no type at all, any
    ``text/*``, or one of ``LOG_UPLOAD_TYPES``."""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    return not media or media.startswith("text/") or media in LOG_UPLOAD_TYPES


def check_declared_length(request, bound: int = LOG_UPLOAD_MAX_REQUEST_BYTES) -> None:
    """Refuse a body whose declared length is over ``bound``, before it is parsed.

    Call it before ``request.data`` is touched: nothing is read here, only the header.
    A body that declares no length is not refused here; it is held to the cap below."""
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise ValidationError({"detail": "Content-Length is not a number"}) from None
    if declared > bound:
        raise LogUploadTooLarge()


def refuse_invalid_text(errors) -> None:
    """Raise what a serializer that did not validate ``content`` is answered with: 413 if
    the text was refused for its length, else the 400 ``raise_exception=True`` would raise.

    ``errors`` is ``serializer.errors``. A message is never looked at, only its code, so
    nothing the caller sent can reach the answer."""
    if any(error.code == "max_length" for error in errors.get("content", [])):
        raise LogUploadTooLarge()
    raise ValidationError(errors)


def check_log_text(text: str) -> str:
    """The text, if it is within ``LOG_UPLOAD_MAX_BYTES`` in the UTF-8 bytes it is; else
    ``LogUploadTooLarge`` (413).

    The serializer's ``max_length`` counts characters and a character is one to four bytes,
    so this is the check the engine's own would make. A lone surrogate (which the serializer
    refuses, but this does not depend on that) counts as the three bytes it would take,
    rather than raising."""
    if len(text.encode("utf-8", errors="surrogatepass")) > LOG_UPLOAD_MAX_BYTES:
        raise LogUploadTooLarge()
    return text


def read_log_text(uploaded_file) -> str:
    """The text of an uploaded log file, or the refusal that says why not.

    Raises ``LogUploadNotText`` (415) for a type that is not a log's or content that is
    not text, and ``LogUploadTooLarge`` (413) for a file over ``LOG_UPLOAD_MAX_BYTES``.
    Reads nothing for a refusal by type or by size, and never more than one byte past
    the cap for any other. Decodes as UTF-8 and drops what is not, as it always did."""
    if not is_log_type(getattr(uploaded_file, "content_type", None)):
        raise LogUploadNotText()
    size = getattr(uploaded_file, "size", None)
    if size is not None and size > LOG_UPLOAD_MAX_BYTES:
        raise LogUploadTooLarge()

    chunks = []
    held = 0
    while held <= LOG_UPLOAD_MAX_BYTES:
        # Not past one byte over the cap, whatever the file said its size was.
        chunk = uploaded_file.read(min(LOG_UPLOAD_READ_CHUNK_BYTES, LOG_UPLOAD_MAX_BYTES + 1 - held))
        if not chunk:
            break
        chunks.append(chunk)
        held += len(chunk)
    if held > LOG_UPLOAD_MAX_BYTES:
        raise LogUploadTooLarge()

    content = b"".join(chunks)
    if b"\x00" in content[:LOG_UPLOAD_SNIFF_BYTES]:
        raise LogUploadNotText()
    return content.decode("utf-8", errors="ignore")
