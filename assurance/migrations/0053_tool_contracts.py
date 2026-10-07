# Tool contracts, recorded per registration (append-only), and the bindings that
# tie an approval or a claim to the contract it was made under
# (assurance.tool_contract).
#
# Numbered 0053 and depending on 0051 on purpose: 0052 is being added on a
# parallel branch. Whichever lands second has its dependency moved onto the other.

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models

_ASSET_KINDS = [
    ("model", "Model"),
    ("agent", "Agent"),
    ("tool", "Tool"),
    ("api", "API"),
    ("gateway", "AI gateway"),
    ("vector_db", "Vector database"),
    ("service_account", "Service account"),
    ("data_store", "Data store"),
    ("mcp_server", "MCP server"),
    ("skill", "Agent skill"),
    ("other", "Other"),
]


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0051_closure_evidence_forward"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ToolContract",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("uuid", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False)),
                ("tool_kind", models.CharField(choices=_ASSET_KINDS, max_length=32)),
                ("tool_identifier", models.CharField(max_length=1024)),
                ("digest", models.CharField(max_length=64)),
                ("contract", models.JSONField(default=dict)),
                ("recorded_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "asset",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="tool_contracts",
                        to="assurance.asset",
                    ),
                ),
                (
                    "deployment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tool_contracts",
                        to="assurance.deployment",
                    ),
                ),
            ],
            options={
                "ordering": ["deployment", "tool_kind", "tool_identifier", "id"],
                "indexes": [
                    models.Index(
                        fields=["deployment", "tool_kind", "tool_identifier"],
                        name="assurance_toolcontract_key",
                    )
                ],
            },
        ),
        migrations.CreateModel(
            name="ToolContractBinding",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("uuid", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False)),
                ("claim_fingerprint", models.CharField(blank=True, db_index=True, default="", max_length=64)),
                ("tool_kind", models.CharField(choices=_ASSET_KINDS, max_length=32)),
                ("tool_identifier", models.CharField(max_length=1024)),
                ("contract_digest", models.CharField(max_length=64)),
                ("bound_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("released_at", models.DateTimeField(blank=True, null=True)),
                ("invalidated_at", models.DateTimeField(blank=True, null=True)),
                ("invalidation_reason", models.TextField(blank=True)),
                (
                    "bound_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="tool_contract_bindings",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "claim",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="tool_contract_bindings",
                        to="assurance.assuranceclaim",
                    ),
                ),
                (
                    "contract",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="bindings",
                        to="assurance.toolcontract",
                    ),
                ),
                (
                    "deployment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tool_contract_bindings",
                        to="assurance.deployment",
                    ),
                ),
                (
                    "workflow",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tool_contract_bindings",
                        to="assurance.approvedworkflow",
                    ),
                ),
            ],
            options={
                "ordering": ["deployment", "tool_kind", "tool_identifier", "id"],
                "indexes": [
                    models.Index(fields=["deployment", "released_at"], name="assurance_toolbinding_live")
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(~models.Q(claim_fingerprint=""), ("workflow__isnull", True)),
                            models.Q(("claim_fingerprint", ""), ("workflow__isnull", False)),
                            _connector="OR",
                        ),
                        name="ck_tool_binding_one_subject",
                    ),
                    models.UniqueConstraint(
                        condition=models.Q(("released_at__isnull", True), ("workflow__isnull", True)),
                        fields=("deployment", "claim_fingerprint", "tool_kind", "tool_identifier"),
                        name="uq_live_claim_tool_binding",
                    ),
                    models.UniqueConstraint(
                        condition=models.Q(("released_at__isnull", True), ("workflow__isnull", False)),
                        fields=("workflow", "tool_kind", "tool_identifier"),
                        name="uq_live_workflow_tool_binding",
                    ),
                ],
            },
        ),
    ]
