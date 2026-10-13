"""The data routes: data health (MVP step 10; ``docs/economics/spec-v1.md``, section
29.7) and one normalization for a deployment (MVP step 12; section 12.9).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves these two routes unserved and nothing else -- not the
other economics routes, not the URLconf, not a stop.

- ``GET deployments/<uuid>/economics/data-health/``: every feed source a run of the
  deployment can read (:func:`assurance.economics.feeds.data_health`), on today's
  date: its latest version, the version a run uses, its age, SLA and state
  (``fresh``, ``stale``, ``blocked`` or ``missing``), the last fetch that failed (its
  code only) and the Unknowns it causes -- the deployment's current parameters that
  name it, where it is blocked or missing.

- ``GET deployments/<uuid>/economics/normalization/?<query>``: one amount, recorded
  on its event date, normalized for a run of the deployment as of its valuation date
  (:func:`assurance.economics.normalization_service.normalize_for`, section 12.8): the
  engine's provenance record (section 12.6), its ``conflicts``, its
  ``primary_unavailable`` steps and its downgrades, over the source versions a run of
  the deployment may use on that date and nothing else -- platform-wide and its own,
  never another deployment's. The query names the amount and its currency, the two
  dates, the base and reporting currencies, the FX policy's providers in order and the
  base currency's cost index (:data:`NORMALIZATION_REQUIRED`), and may name the rest
  of the policy (:data:`NORMALIZATION_OPTIONAL`, the engine's defaults otherwise). A
  normalization the books cannot make is ``unavailable``, with its reason, and still
  answered 200: it is the record. A query the engine refuses -- a malformed amount, a
  policy it does not accept, an event after its valuation date -- is 400 with the
  engine's code.

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account, and a deployment the caller cannot see is 404 whether or not it exists; a
viewer reads. Data health takes no query parameter (400 for any, never ignored); the
normalization route reads its query strictly, as the read routes the dashboard needs
do (section 30): only the keys it names, each once (``field_unrecognised``,
``field_malformed``), every required one present (``field_missing``). Each answers
canonical JSON: the same stored rows on the same date give the same bytes. The
normalization is answered ``no-store``, as every figure of a tenant's is, and while
economics cannot read its currency table it is 503 and computes nothing. Neither
writes anything.

None of it is a stop, and neither route reads or writes anything a stop or the
decision reads: each is in ``safety.stops.NOT_STOPS``, and neither holds a lock or a
transaction. The module does nothing at import but define its views, and imports the
feed module (and through it the outbound client), the normalization service and the
engine only inside them: nothing Django loads at start imports them.
"""

from __future__ import annotations

import json
import re
from datetime import date

from django.http import HttpResponse
from django.urls import path
from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView

from .api import _deployment, _table_unavailable

#: The query keys a normalization is asked with, every one of them required: the
#: amount and its currency, its two dates, the base and reporting currencies, the FX
#: policy's providers (comma-separated, in order: the first with a usable rate is the
#: primary, section 12.8) and the base currency's cost index (its series, geography,
#: category and base; its currency is the base currency's, section 12.4).
NORMALIZATION_REQUIRED = (
    "amount",
    "currency",
    "event_date",
    "valuation_date",
    "base_currency",
    "reporting_currency",
    "providers",
    "index_series_id",
    "index_geography",
    "index_category",
    "index_base",
)
#: The rest of the policy, each at the engine's default where it is not named
#: (``FXPolicy``, ``NormalizationPolicy``): the rate types accepted (comma-separated,
#: in order), the weekend and holiday rule, the missing-rate rule, the interpolation
#: gap and freshness limits in days, and how many months the index may lag.
NORMALIZATION_OPTIONAL = (
    "rate_types",
    "weekend_holiday_rule",
    "missing_rate",
    "max_interpolation_gap_days",
    "freshness_days",
    "index_max_lag_months",
)
#: The most digits a day or month limit may be written with: a longer one is refused
#: before it is read as a number.
MAX_LIMIT_DIGITS = 4
#: What the normalization's answer carries: a tenant's figure is never kept by a cache
#: on the way (section 30).
NO_STORE = "no-store"

_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def canonical_bytes(document) -> bytes:
    """One spelling of the answer: sorted keys, no whitespace, UTF-8."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class DataHealthView(APIView):
    """Feed freshness, source failures and the Unknowns they cause, for one deployment."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        if request.query_params:
            raise ValidationError(
                {"code": "field_malformed", "detail": "the data-health route takes no query parameter"}
            )
        from . import feeds

        return HttpResponse(canonical_bytes(feeds.data_health(deployment)), content_type="application/json")


def _refused(code: str, detail: str) -> ValidationError:
    return ValidationError({"code": code, "detail": detail})


def strict_query(query, required: tuple[str, ...], optional: tuple[str, ...]) -> dict[str, str]:
    """The query string read strictly (section 30): only the keys named
    (``field_unrecognised`` otherwise), each given once (``field_malformed``), and
    every required one present (``field_missing``)."""
    allowed = (*required, *optional)
    unknown = sorted(set(query) - set(allowed))
    if unknown:
        raise _refused("field_unrecognised", f"query: {unknown}: this route reads only {list(allowed)}")
    for key in query:
        if len(query.getlist(key)) != 1:
            raise _refused("field_malformed", f"{key} is given once")
    missing = [key for key in required if key not in query]
    if missing:
        raise _refused("field_missing", f"query: {missing}")
    return {key: query[key] for key in query}


def _day(query: dict[str, str], key: str) -> date:
    """``query[key]`` read as a calendar date, ``YYYY-MM-DD`` and nothing else."""
    text = query[key]
    if _DAY.fullmatch(text):
        try:
            return date.fromisoformat(text)
        except ValueError:
            pass
    raise _refused("field_malformed", f"{key} is a date, YYYY-MM-DD")


def _names(query: dict[str, str], key: str) -> tuple[str, ...] | None:
    """``query[key]`` read as a comma-separated list of names, in order: none of them
    empty or padded. ``None`` where the key is absent."""
    text = query.get(key)
    if text is None:
        return None
    names = tuple(text.split(","))
    if any(not name or name != name.strip() for name in names):
        raise _refused("field_malformed", f"{key} is a comma-separated list of names, none of them blank")
    return names


def _limit(query: dict[str, str], key: str) -> int | None:
    """``query[key]`` read as a whole number of days or months: ASCII digits, no sign
    and no leading zero, at most :data:`MAX_LIMIT_DIGITS` of them. ``None`` where the
    key is absent."""
    text = query.get(key)
    if text is None:
        return None
    if not (text.isascii() and text.isdigit() and len(text) <= MAX_LIMIT_DIGITS and (text == "0" or text[0] != "0")):
        raise _refused("field_malformed", f"{key} is a whole number, no leading zero, at most {MAX_LIMIT_DIGITS} digits")
    return int(text)


def normalization_request(query: dict[str, str]):
    """``(native, event_date, valuation_date, policy)`` from a strict normalization
    query. The engine's own checks refuse what it does not accept (``MoneyRefused``):
    an amount not in the one spelling, a currency it does not know, a policy it does
    not hold to (``policy_invalid``)."""
    from .engine.cost_index import IndexSelector
    from .engine.fx import FXPolicy
    from .engine.money import Money
    from .engine.normalization import NormalizationPolicy

    event_date, valuation_date = _day(query, "event_date"), _day(query, "valuation_date")
    rules = {
        name: value
        for name, value in (
            ("rate_types", _names(query, "rate_types")),
            ("weekend_holiday_rule", query.get("weekend_holiday_rule")),
            ("missing_rate", query.get("missing_rate")),
            ("max_interpolation_gap_days", _limit(query, "max_interpolation_gap_days")),
            ("freshness_days", _limit(query, "freshness_days")),
        )
        if value is not None
    }
    lag = _limit(query, "index_max_lag_months")
    native = Money.parse(query["amount"], query["currency"])
    policy = NormalizationPolicy(
        query["base_currency"],
        query["reporting_currency"],
        FXPolicy(_names(query, "providers"), **rules),
        IndexSelector(
            query["index_series_id"],
            query["index_geography"],
            query["index_category"],
            query["index_base"],
            query["base_currency"],
        ),
        **({} if lag is None else {"index_max_lag_months": lag}),
    )
    return native, event_date, valuation_date, policy


class NormalizationView(APIView):
    """One amount normalized for a run of one deployment, as of its valuation date."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        query = strict_query(request.query_params, NORMALIZATION_REQUIRED, NORMALIZATION_OPTIONAL)
        from . import normalization_service
        from .engine import currency
        from .engine.money import MoneyRefused

        try:
            native, event_date, valuation_date, policy = normalization_request(query)
            record = normalization_service.normalize_for(
                deployment, native, event_date=event_date, valuation_date=valuation_date, policy=policy
            ).as_dict()
        except currency.CurrencyTableInvalid:
            return _table_unavailable()
        except MoneyRefused as refused:
            raise _refused(refused.code, refused.detail or refused.code) from None
        document = {"deployment": str(deployment.uuid), "normalization": record}
        return HttpResponse(
            canonical_bytes(document), content_type="application/json", headers={"Cache-Control": NO_STORE}
        )


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/data-health/",
        DataHealthView.as_view(),
        name="deployment-economics-data-health",
    ),
    path(
        "deployments/<uuid:uuid>/economics/normalization/",
        NormalizationView.as_view(),
        name="deployment-economics-normalization",
    ),
]
