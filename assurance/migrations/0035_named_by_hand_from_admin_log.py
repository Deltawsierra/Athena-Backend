import json

from django.db import migrations

#: ``assets.NAMED_BY_HAND`` when this migration was written. Spelled here, not
#: imported: a migration records what it did, and the constant may move on.
NAMED_BY_HAND = "named_by_hand"
#: ``LogEntry.CHANGE``.
CHANGE = 2
_BATCH = 500


def _renamed(message) -> bool:
    """Whether an admin change message says the object's OWN name was changed.

    The admin writes ``[{"changed": {"fields": ["Name", ...]}}]`` for the object
    edited, with labels spelled untranslated; an entry that also carries ``name``
    and ``object`` is a change to an inline's object, not to this one."""
    try:
        entries = json.loads(message or "[]")
    except (TypeError, ValueError):
        return False
    if not isinstance(entries, list):
        return False
    for entry in entries:
        changed = entry.get("changed") if isinstance(entry, dict) else None
        if not isinstance(changed, dict) or "object" in changed:
            continue
        fields = changed.get("fields")
        if isinstance(fields, list) and any(str(f).strip().lower() == "name" for f in fields):
            return True
    return False


def mark_names_people_gave(apps, schema_editor):
    """Mark every asset a person renamed in the admin before the admin marked it.

    The admin marks a rename as it saves it (``assets.NAMED_BY_HAND``), and a
    settle or a re-declaration renames a row only while it is unmarked. A rename
    made before that shipped carries no mark, and the rows that settle renames --
    rows the old identity rules wrote -- exist only from before it: a tool a person
    had called "GitHub (prod)" went back to ``github`` on the first rescan. The
    admin's own change log is the record of who renamed what, so it is read here.
    """
    try:
        LogEntry = apps.get_model("admin", "LogEntry")
        ContentType = apps.get_model("contenttypes", "ContentType")
    except LookupError:
        return
    Asset = apps.get_model("assurance", "Asset")
    content_type = ContentType.objects.filter(app_label="assurance", model="asset").first()
    if content_type is None:
        return
    renamed: set[int] = set()
    entries = LogEntry.objects.filter(content_type=content_type, action_flag=CHANGE)
    for object_id, message in entries.values_list("object_id", "change_message").iterator():
        if not _renamed(message):
            continue
        try:
            renamed.add(int(str(object_id).strip()))
        except (TypeError, ValueError):
            continue
    pks = sorted(renamed)
    for start in range(0, len(pks), _BATCH):
        for asset in Asset.objects.filter(pk__in=pks[start:start + _BATCH]):
            metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
            if metadata.get(NAMED_BY_HAND) is True:
                continue
            asset.metadata = {**metadata, NAMED_BY_HAND: True}
            asset.save(update_fields=["metadata"])


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0034_stamp_unchanged_identities"),
        ("admin", "0003_logentry_add_action_flag_choices"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        # Not reversed: the mark is read only by code this migration ships with,
        # and removing it would also remove marks the admin set since.
        migrations.RunPython(mark_names_people_gave, migrations.RunPython.noop),
    ]
