"""What every append-only record refuses, beyond its own ``save`` and ``delete``.

Every append-only record refuses an update or a delete of a recorded row in its
``save`` and ``delete``. Four more ORM writes reach a recorded row past those, and
each is refused here, with the record's own exception and message:

1. **A bulk rewrite.** A queryset ``update()``, ``bulk_update()`` or ``delete()``
   never calls ``save`` or ``delete``. :class:`HistoryQuerySet`, every record's
   default queryset, refuses all three -- ``bulk_update`` before Django's own atomic
   block, so the caller's transaction stays usable -- and so does every manager built
   from it, related managers included.

2. **An upsert.** ``bulk_create(objs, update_conflicts=True, update_fields=...,
   unique_fields=...)`` is ``INSERT ... ON CONFLICT DO UPDATE``: it rewrites the
   recorded row that holds the key, in place. :class:`HistoryQuerySet` refuses it. A
   plain ``bulk_create`` of new rows still inserts them, as before (the edge history
   notes its changes that way). ``ignore_conflicts=True`` is not refused: a row whose
   key is taken is dropped and the recorded row stays exactly as it was, so nothing
   recorded is rewritten.

3. **A new instance carrying a recorded row's key.** ``Model(pk=<recorded>,
   ...).save()`` passes a ``save`` that checks only ``_state.adding``, and Django then
   tries an ``UPDATE`` before an ``INSERT``. Every record's ``save`` writes an INSERT
   and nothing else (``force_insert``), so that save fails on the key instead
   (``IntegrityError``); a save asking for an update (``force_update``,
   ``update_fields``) is refused outright. ``objects.create`` already inserts.

4. **A move through a reverse foreign key.** ``parent.<rows>.add(row)`` -- bulk, the
   default -- moves a recorded row to another parent with an ``UPDATE`` through the
   BASE manager, past every queryset refusal; ``set`` adds the same way, and on a
   nullable key ``remove`` and ``clear`` null it. So a history row's foreign key has
   no reverse accessor (``related_name="+"``) wherever nothing reads one, and is a
   :class:`HistoryForeignKey` where something does: its accessor reads as before
   (``all``, ``filter``, ``count``, a prefetch) and refuses ``add``, ``remove``,
   ``clear`` and ``set`` before any SQL.

None of this touches the base manager, which stays Django's plain one on every
append-only record. The deployment's cascade and removing an operator -- a stop
(``accounts:user-detail`` DELETE), which nulls every account column that names them
-- write through it, and nothing here may hold either back.
"""

from __future__ import annotations

from django.db import models
from django.db.models.fields.related_descriptors import ReverseManyToOneDescriptor
from django.utils.functional import cached_property


class HistoryQuerySet(models.QuerySet):
    """The queryset an append-only record's default manager is built from: it refuses
    a bulk ``update``, ``bulk_update`` and ``delete`` and an upsert, none of which the
    record's ``save`` or ``delete`` sees, with the record's own refusal: ``refused`` is
    its exception, ``rewritten`` and ``deleted`` what it says."""

    refused: type[Exception] = ValueError
    rewritten = "A recorded row is history and is never rewritten; record a new row."
    deleted = "A recorded row is history and is never deleted."

    def update(self, **kwargs):
        raise self.refused(self.rewritten)

    # Refused here, not left to reach update(): Django's bulk_update would refuse inside
    # its own atomic block and leave the caller's transaction unusable.
    def bulk_update(self, objs, fields, batch_size=None):
        raise self.refused(self.rewritten)

    def delete(self):
        raise self.refused(self.deleted)

    delete.queryset_only = True

    # Refused before Django's own atomic block, so the caller's transaction stays
    # usable. Django's own signature, so an upsert asked for by position is refused too.
    def bulk_create(
        self,
        objs,
        batch_size=None,
        ignore_conflicts=False,
        update_conflicts=False,
        update_fields=None,
        unique_fields=None,
    ):
        if update_conflicts:
            raise self.refused(self.rewritten)
        # Not an upsert. Django reads update_fields and unique_fields only for one, so
        # they are not passed on, and this override names no column it could write.
        return super().bulk_create(objs, batch_size=batch_size, ignore_conflicts=ignore_conflicts)


def insert_only(row, kwargs: dict, refusal: Exception) -> dict:
    """The ``save`` keywords that write ``row`` as a NEW row and nothing else, for an
    append-only record's ``save`` to pass on. Raises ``refusal`` (the record's own) for
    a recorded row, or for a save that asks for an update (``force_update``,
    ``update_fields``). A new instance carrying a recorded row's key is then an INSERT,
    which fails on the key rather than overwriting that row."""
    if not row._state.adding or kwargs.get("force_update") or kwargs.get("update_fields") is not None:
        raise refusal
    return {**kwargs, "force_insert": True}


def _refused_move(manager):
    """The refusal of a move through ``manager``, the reverse accessor of a
    :class:`HistoryForeignKey`: the record's own exception, naming the accessor."""
    history = manager.model._default_manager.all()
    parent = manager.field.remote_field.model._meta.model_name
    return history.refused(
        f"A recorded {manager.model._meta.verbose_name} is history and is never moved by "
        f"{parent}.{manager.field.remote_field.accessor_name}; record a new row."
    )


class _HistoryRowsDescriptor(ReverseManyToOneDescriptor):
    """The reverse accessor of a :class:`HistoryForeignKey`: Django's related manager,
    less every method that moves a recorded row. Its async forms call these."""

    @cached_property
    def related_manager_cls(self):
        rows = super().related_manager_cls

        class HistoryRowsManager(rows):
            def add(self, *objs, bulk=True):
                raise _refused_move(self)

            add.alters_data = True

            def remove(self, *objs, bulk=True):
                raise _refused_move(self)

            remove.alters_data = True

            def clear(self, *, bulk=True):
                raise _refused_move(self)

            clear.alters_data = True

            def set(self, objs, *, bulk=True, clear=False):
                raise _refused_move(self)

            set.alters_data = True

        return HistoryRowsManager


class HistoryForeignKey(models.ForeignKey):
    """An append-only record's foreign key whose reverse accessor something reads. The
    accessor reads; it never moves a recorded row (:class:`_HistoryRowsDescriptor`).

    To migrations it is a plain ``ForeignKey``: the refusal is code, not schema, and a
    migration's historical model writes no history."""

    related_accessor_class = _HistoryRowsDescriptor

    def deconstruct(self):
        name, _path, args, kwargs = super().deconstruct()
        return name, "django.db.models.ForeignKey", args, kwargs
