from django.db import migrations, models


def mark_signed(apps, schema_editor):
    """Commands that already carry a signature are marked signed."""
    FailsafeCommand = apps.get_model("failsafe", "FailsafeCommand")
    signed = [pk for pk, signatures in FailsafeCommand.objects.values_list("pk", "signatures").iterator() if signatures]
    for start in range(0, len(signed), 500):
        FailsafeCommand.objects.filter(pk__in=signed[start:start + 500]).update(signed=True)


class Migration(migrations.Migration):

    dependencies = [
        ("failsafe", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="failsafecommand",
            name="signed",
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(mark_signed, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(fields=["created_at"], name="fsc_ct"),
        ),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(fields=["engine_id", "created_at"], name="fsc_eng_ct"),
        ),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(fields=["status", "created_at"], name="fsc_st_ct"),
        ),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(fields=["engine_id", "status", "created_at"], name="fsc_eng_st_ct"),
        ),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(fields=["status", "action", "signed", "created_at"], name="fsc_st_act_sig_ct"),
        ),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(
                fields=["engine_id", "status", "action", "signed", "created_at"], name="fsc_eng_st_act_sig_ct"
            ),
        ),
        migrations.AddIndex(
            model_name="failsafecommand",
            index=models.Index(fields=["initiator", "engine_id", "action", "status", "signed"], name="fsc_draft_lookup"),
        ),
    ]
