"""The two worked examples of the owner's specification, as known answers.

SYNTHETIC / ILLUSTRATIVE. Every figure here is illustrative: section 30's are the
specification's own ("numbers below are fabricated to demonstrate product
behavior"), and section 31 gives no figures at all, so its are made up here and
labelled so. None is a customer's figure or a benchmark, and none may be cited as
one. Each expected low, base and high is computed by hand in the comments, in the
direction each input moves the loss (``docs/economics/spec-v1.md``, section 21).
These are the known-answer seeds Minotaur's economic-exposure tests start from
(step 9).

Where the specification gives a range and no base, the base is the range's
midpoint, a stated mechanical rule and not an estimate.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from assurance.economics.engine.formulas import ESTIMATED, UNKNOWN, evaluate
from assurance.economics.engine.loss import InsurancePolicy, LossEvent, assess
from assurance.economics.engine.money import Money
from assurance.economics.engine.parameters import MONEY_UNITS, POINTS, Parameter, Unit

LABEL = "SYNTHETIC / ILLUSTRATIVE"
AS_OF = date(2026, 10, 6)


def p(name, unit, low, base, high, source, why) -> Parameter:
    unit = Unit(unit)

    def value(figure):
        return Money(Decimal(figure), "USD") if unit in MONEY_UNITS else Decimal(figure)

    return Parameter(name, unit, source, value(low), value(base), value(high), f"{LABEL}: {why}")


def figures(component) -> tuple[Decimal, ...]:
    return tuple(component.at(point).amount for point in POINTS)


def total(range_) -> tuple[Decimal, ...]:
    return tuple(range_.at(point).amount for point in POINTS)


# ======================================================================
# Section 30, worked example A: the bank payment agent
# ======================================================================
#
# Achilles changed a transfer's destination after approval in a scoped test:
# 7 unauthorized effects in 20 valid attempts. Transactions/day 18,000; average
# relevant transfer USD 25,000; repeatable window 0.5 to 2.0 hours; recovery 70%
# to 95%; incident response USD 80k to 250k; legal/regulatory response USD 150k
# to 1.5M; remediation USD 180k to 420k.


def example_a() -> LossEvent:
    direct = evaluate(
        "unauthorized-transfers",
        "direct_financial",
        "repeat_in_window",
        1,
        {
            "transactions_per_day": p("transactions_per_day", "count_per_day", "18000", "18000", "18000",
                                      "CUSTOMER_PROVIDED", "section 30, transactions/day"),
            # 0.5 to 2.0 hours; base the midpoint, 1.25.
            "window_hours": p("repeatable_window_hours", "hours", "0.5", "1.25", "2.0",
                              "EXPERT_ESTIMATE", "section 30, repeatable window"),
            # 7 of 20: the observed proportion, a point. The interval around it is the
            # probabilistic engine's (a later step), not this one's.
            "success_rate": p("observed_success_rate", "ratio", "0.35", "0.35", "0.35",
                              "MYTHOS_OBSERVED", "section 30, 7 unauthorized effects in 20 attempts"),
            "value_per_transaction": p("average_transfer", "money_per_unit", "25000", "25000", "25000",
                                       "CUSTOMER_PROVIDED", "section 30, average relevant transfer"),
            # 70% to 95%; base the midpoint, 82.5%.
            "recovery_rate": p("recovery_rate", "ratio", "0.70", "0.825", "0.95",
                               "CUSTOMER_PROVIDED", "section 30, recovery rate"),
        },
        as_of=AS_OF,
    )
    response = evaluate(
        "incident-response", "incident_response", "lump_sum", 1,
        {"amount": p("incident_response", "money", "80000", "165000", "250000",
                     "EXPERT_ESTIMATE", "section 30, incident response")},
        as_of=AS_OF,
    )
    legal = evaluate(
        "legal-and-regulatory-response", "legal", "lump_sum", 1,
        {"amount": p("legal_regulatory_response", "money", "150000", "825000", "1500000",
                     "EXPERT_ESTIMATE", "section 30, legal/regulatory response (one combined range, filed as legal)")},
        as_of=AS_OF,
    )
    return LossEvent("payment-destination-changed-after-approval", "USD", (direct, response, legal))


def test_example_a_direct_loss():
    # Repeat count: 18,000 a day / 24 = 750 an hour, x the window, x 0.35 succeed.
    # The window and the success rate increase the loss; recovery decreases it, so
    # the LOW reads recovery's HIGH (95%) and the HIGH reads its LOW (70%).
    #
    # low:  750 x 0.5  h = 375    transfers; x 0.35 = 131.25  succeed;
    #       x 25,000 = 3,281,250;  x (1 - 0.95)  = x 0.05  =   164,062.50
    # base: 750 x 1.25 h = 937.5  transfers; x 0.35 = 328.125 succeed;
    #       x 25,000 = 8,203,125;  x (1 - 0.825) = x 0.175 = 1,435,546.875
    # high: 750 x 2.0  h = 1,500  transfers; x 0.35 = 525     succeed;
    #       x 25,000 = 13,125,000; x (1 - 0.70)  = x 0.30  = 3,937,500
    direct = example_a().components[0]
    assert direct.status == ESTIMATED
    assert figures(direct) == (Decimal("164062.50"), Decimal("1435546.875"), Decimal("3937500"))
    assert [c.input.name for c in direct.inputs] == [
        "transactions_per_day", "window_hours", "success_rate", "value_per_transaction", "recovery_rate"
    ]


def test_example_a_event_loss():
    # Gross cash loss, the components summed point by point:
    # low:    164,062.50 +  80,000 +   150,000 =   394,062.50
    # base: 1,435,546.875 + 165,000 +   825,000 = 2,425,546.875
    # high: 3,937,500     + 250,000 + 1,500,000 = 5,687,500
    #
    # The remediation cost (USD 180k to 420k) is the price of the fix, a mitigation
    # option (section 21, a later step), not a loss this event causes: it is not a
    # component here, so pre-control and residual exposure can later be compared
    # against it without counting it twice. Annual frequency is the probabilistic
    # engine's; this is the event's loss given that it happens.
    result = assess(example_a())
    assert result.gross.total.complete
    assert total(result.gross.total) == (Decimal("394062.50"), Decimal("2425546.875"), Decimal("5687500"))
    assert result.gross.total.as_dict()["display"] == {
        "low": "394062.50 USD", "base": "2425546.88 USD", "high": "5687500.00 USD"
    }
    assert result.insured is None
    assert total(result.market_value) == (Decimal(0),) * 3
    # Every component names its formula and every parameter its source.
    record = result.as_dict()
    assert [c["formula"]["formula_id"] for c in record["components"]] == ["repeat_in_window", "lump_sum", "lump_sum"]
    sources = {row["parameter"]["name"]: row["parameter"]["source_type"]
               for c in record["components"] for row in c["inputs"]}
    assert sources["observed_success_rate"] == "MYTHOS_OBSERVED"
    assert sources["average_transfer"] == "CUSTOMER_PROVIDED"
    assert all(row["parameter"]["evidence_ref"].startswith(LABEL)
               for c in record["components"] for row in c["inputs"])


# ======================================================================
# Section 31, worked example B: cross-customer data exposure
# ======================================================================
#
# The specification gives the modelling approach and no figures. Every figure
# below is MADE UP for this test, labelled SYNTHETIC / ILLUSTRATIVE.


def example_b_components():
    affected = p("affected_customers", "count", "20000", "50000", "120000",
                 "MYTHOS_OBSERVED", "made up: reachable records and tested retrieval")
    notification = evaluate(
        "notification", "notification", "per_affected_plus_fixed", 1,
        {
            "affected": affected,
            "unit_cost": p("notice_unit_cost", "money_per_unit", "1.50", "2.00", "3.00",
                           "CUSTOMER_PROVIDED", "made up: per-customer notice cost"),
            "fixed_cost": p("campaign_fixed_cost", "money", "25000", "40000", "60000",
                            "CUSTOMER_PROVIDED", "made up: fixed campaign cost"),
        },
        as_of=AS_OF,
    )
    support = evaluate(
        "support", "notification", "support_contacts", 1,
        {
            "affected": affected,
            "contact_rate": p("support_contact_rate", "ratio", "0.05", "0.10", "0.20",
                              "INDUSTRY_BENCHMARK", "made up: contact rate"),
            "handling_hours": p("handling_hours", "hours", "0.10", "0.15", "0.25",
                                "CUSTOMER_PROVIDED", "made up: average handling time"),
            "loaded_rate": p("support_agent_hourly_rate", "money_per_hour", "40", "55", "70",
                             "CUSTOMER_PROVIDED", "made up: loaded agent rate"),
        },
        as_of=AS_OF,
    )
    forensics = evaluate(
        "forensics", "incident_response", "fixed_plus_hours", 1,
        {
            "fixed_cost": p("forensics_retainer", "money", "50000", "75000", "100000",
                            "CUSTOMER_PROVIDED", "made up: forensics fixed fee"),
            "hourly_rate": p("forensics_rate", "money_per_hour", "300", "400", "500",
                             "CUSTOMER_PROVIDED", "made up: forensics rate"),
            "hours": p("forensics_hours", "hours", "200", "400", "800",
                       "EXPERT_ESTIMATE", "made up: duration and complexity"),
        },
        as_of=AS_OF,
    )
    legal = evaluate(
        "legal", "legal", "fixed_plus_hours", 1,
        {
            "fixed_cost": p("legal_retainer", "money", "25000", "50000", "100000",
                            "CUSTOMER_PROVIDED", "made up: counsel retainer"),
            "hourly_rate": p("external_counsel_hourly_rate", "money_per_hour", "450", "600", "800",
                             "CUSTOMER_PROVIDED", "made up: counsel rate"),
            "hours": p("counsel_hours", "hours", "100", "300", "800",
                       "EXPERT_ESTIMATE", "made up: matter complexity"),
        },
        as_of=AS_OF,
    )
    regulatory = evaluate(
        "regulatory", "regulatory_compliance", "lump_sum", 1,
        {"amount": p("regulatory_bounds", "money", "0", "100000", "500000",
                     "EXPERT_ESTIMATE", "made up: scenario bounds pending legal review, not a fine prediction")},
        as_of=AS_OF,
    )
    churn = evaluate(
        "customer-loss", "customer_loss", "churned_margin", 1,
        {
            "customers": affected,
            # A benchmark, not the customer's own retention data: section 31 says
            # Unknown, and the engine says so.
            "churn_rate": p("churn_rate", "ratio", "0.01", "0.02", "0.04",
                            "INDUSTRY_BENCHMARK", "made up: benchmark churn"),
            "margin_per_customer_per_year": p("margin_per_customer", "money_per_unit", "120", "150", "200",
                                              "CUSTOMER_PROVIDED", "made up: margin per customer"),
            "recovery_years": p("recovery_years", "years", "1", "1", "2", "EXPERT_ESTIMATE", "made up"),
        },
        as_of=AS_OF,
    )
    return notification, support, forensics, legal, regulatory, churn


def example_b() -> LossEvent:
    return LossEvent("cross-customer-data-exposure", "USD", example_b_components())


def example_b_policy() -> InsurancePolicy:
    def term(name, figure, why):
        return p(name, "money", figure, figure, figure, "CUSTOMER_PROVIDED", why)

    return InsurancePolicy(
        deductible=term("insurance_deductible", "100000", "made up: deductible"),
        limit=term("insurance_limit", "1000000", "made up: aggregate limit"),
        sublimits={"notification": term("insurance_sublimit:notification", "150000", "made up: notification sublimit")},
        exclusions=frozenset({"regulatory_compliance"}),
    )


def test_example_b_components():
    notification, support, forensics, legal, regulatory, churn = example_b_components()
    # Notification = affected x unit cost + fixed campaign cost.
    #   low:   20,000 x 1.50 +  25,000 =  30,000 +  25,000 =  55,000
    #   base:  50,000 x 2.00 +  40,000 = 100,000 +  40,000 = 140,000
    #   high: 120,000 x 3.00 +  60,000 = 360,000 +  60,000 = 420,000
    assert figures(notification) == (Decimal(55000), Decimal(140000), Decimal(420000))
    # Support = affected x contact rate x handling hours x loaded rate.
    #   low:   20,000 x 0.05 = 1,000 contacts x 0.10 h =   100 h x 40 =   4,000
    #   base:  50,000 x 0.10 = 5,000 contacts x 0.15 h =   750 h x 55 =  41,250
    #   high: 120,000 x 0.20 = 24,000 contacts x 0.25 h = 6,000 h x 70 = 420,000
    assert figures(support) == (Decimal(4000), Decimal(41250), Decimal(420000))
    # Forensics = fixed + rate x hours.
    #   low:   50,000 + 300 x 200 =  50,000 +  60,000 = 110,000
    #   base:  75,000 + 400 x 400 =  75,000 + 160,000 = 235,000
    #   high: 100,000 + 500 x 800 = 100,000 + 400,000 = 500,000
    assert figures(forensics) == (Decimal(110000), Decimal(235000), Decimal(500000))
    # Legal = fixed + counsel rate x hours.
    #   low:   25,000 + 450 x 100 =  25,000 +  45,000 =  70,000
    #   base:  50,000 + 600 x 300 =  50,000 + 180,000 = 230,000
    #   high: 100,000 + 800 x 800 = 100,000 + 640,000 = 740,000
    assert figures(legal) == (Decimal(70000), Decimal(230000), Decimal(740000))
    # Regulatory: scenario bounds as given, 0 / 100,000 / 500,000.
    assert figures(regulatory) == (Decimal(0), Decimal(100000), Decimal(500000))
    # Customer loss: unknown, because the churn rate is a benchmark.
    assert (churn.status, churn.unknown_reason, churn.missing) == (UNKNOWN, "input_source_not_accepted", ("churn_rate",))


def test_example_b_gross_loss_is_a_floor_while_customer_loss_is_unknown():
    # Gross cash loss of the KNOWN components:
    #   low:   55,000 +   4,000 + 110,000 +  70,000 +       0 =   239,000
    #   base: 140,000 +  41,250 + 235,000 + 230,000 + 100,000 =   746,250
    #   high: 420,000 + 420,000 + 500,000 + 740,000 + 500,000 = 2,580,000
    # Customer loss is unknown, so this is "at least", never the event's loss.
    result = assess(example_b())
    gross = result.gross.total
    assert total(gross) == (Decimal(239000), Decimal(746250), Decimal(2580000))
    assert not gross.complete and gross.unknown == ("customer-loss",)
    assert result.as_dict()["unknown_components"] == ["customer-loss"]


def test_example_b_insurance_applied_once_after_the_gross_components():
    # Policy (made up): deductible 100,000; aggregate limit 1,000,000; notification
    # sublimit 150,000; regulatory excluded. Notification and support are both the
    # notification family, so the sublimit caps their sum.
    #
    # low:  covered = min(55,000 + 4,000, 150,000) = 59,000 + forensics 110,000
    #               + legal 70,000 = 239,000 (regulatory 0 excluded)
    #       recovery = min(239,000 - 100,000, 1,000,000) = 139,000
    #       retained = 239,000 - 139,000 = 100,000
    # base: covered = min(140,000 + 41,250, 150,000) = 150,000 + 235,000 + 230,000 = 615,000
    #       recovery = min(615,000 - 100,000, 1,000,000) = 515,000
    #       retained = 746,250 - 515,000 = 231,250
    #       (the deductible 100,000 + notification over its sublimit 31,250
    #        + excluded regulatory 100,000)
    # high: covered = min(420,000 + 420,000, 150,000) = 150,000 + 500,000 + 740,000 = 1,390,000
    #       recovery = min(1,390,000 - 100,000, 1,000,000) = 1,000,000 (the limit)
    #       retained = 2,580,000 - 1,000,000 = 1,580,000
    result = assess(example_b(), example_b_policy())
    insured = result.insured
    assert [insured.points[p].recovery.amount for p in POINTS] == [Decimal(139000), Decimal(515000), Decimal(1000000)]
    assert total(insured.retained) == (Decimal(100000), Decimal(231250), Decimal(1580000))
    # Still a floor: customer loss is unknown, and insurance does not make it known.
    assert not insured.retained.complete and insured.retained.unknown == ("customer-loss",)
    assert insured.points[POINTS[1]].covered_by_family["notification"].amount == 150000
    assert "regulatory_compliance" in insured.points[POINTS[1]].uncovered_families
