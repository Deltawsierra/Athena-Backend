"""Run Mythos-Core's pin guard without importing mythos_core.

Copied byte for byte from Mythos-Core's templates/pin_bootstrap.py; the guard
refuses a copy whose sha256 is not its BOOTSTRAP_SHA256. It reads pinguard.py
from pip's RECORD of the installed mythos-core, checking the sha256 pip recorded,
or from the checkout an editable install's direct_url.json names, and runs it by
path. Anything that stops the guard judging the run is a refusal, never a pass.
"""

import base64
import hashlib
import json
import pathlib
import types
import urllib.parse
import urllib.request
from importlib import metadata
from typing import Any

GUARD = "mythos_core/pinguard.py"


class PinGuardRefusal(Exception):
    """The pin guard refused this run, or could not be loaded to judge it."""


def load_guard() -> types.ModuleType:
    dist = metadata.distribution("mythos-core")
    older = "the installed mythos-core has no pinguard.py: move the pin to a commit with one"
    entry = next((f for f in dist.files or () if str(f) == GUARD), None)
    if entry is not None:
        path, data = pathlib.Path(str(entry.locate())), entry.read_binary()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        if entry.hash is None or (entry.hash.mode, entry.hash.value) != ("sha256", digest.decode()):
            raise PinGuardRefusal(f"{path} is not the file pip installed: its sha256 differs")
    else:
        info = json.loads(dist.read_text("direct_url.json") or "{}")
        if (info.get("dir_info") or {}).get("editable") is not True:
            raise PinGuardRefusal(older)
        url = urllib.parse.urlsplit(info["url"])
        local = url.path if url.netloc.lower() in ("", "localhost") else f"//{url.netloc}{url.path}"
        path = pathlib.Path(urllib.request.url2pathname(local), "src", *GUARD.split("/"))
        if not path.is_file():
            raise PinGuardRefusal(older)
        data = path.read_bytes()
    guard = types.ModuleType("_mythos_core_pinguard")
    guard.__file__ = str(path)
    exec(compile(data, str(path), "exec"), guard.__dict__)
    if guard.BOOTSTRAP_SHA256 != hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest():
        raise PinGuardRefusal(f"{__file__} is not a byte-for-byte copy of the stub {path} pins")
    return guard


def enforce(
    root: object, roster: object, environ: object = None, refusal: type[Exception] = PinGuardRefusal
) -> Any:
    try:
        return load_guard().enforce(root, roster, environ=environ)
    except Exception as exc:  # whatever stops the guard judging the run refuses it
        why = str(exc)
        if type(exc).__name__ != "PinGuardError":  # the guard's own refusal says it all
            why = (
                f"pin guard: refused, because the guard could not run ({type(exc).__name__}): {why}"
            )
        raise refusal(why) from exc
