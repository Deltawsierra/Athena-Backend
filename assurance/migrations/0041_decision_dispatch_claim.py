from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0040_decision_dispatch_owed"),
    ]

    operations = [
        migrations.AddField(
            model_name="decisiondispatchdue",
            name="requests",
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AddField(
            model_name="decisiondispatchdue",
            name="running_until",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="decisiondispatchdue",
            name="run_token",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]
