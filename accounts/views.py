import logging

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import ProtectedError

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.serializers import UserSerializer
from accounts.permissions import IsAdmin

User = get_user_model()
logger = logging.getLogger(__name__)


def _deactivate_and_revoke(user):
    """Deactivate ``user`` and revoke its tokens: it can no longer sign a
    command, refresh, or be read as an operator.

    A deactivated account fails SimpleJWT's active-user check, so its access
    tokens stop working at once; blacklisting its outstanding refresh tokens
    stops new access being minted. This is the fallback when a protected
    reference keeps the row from being deleted."""
    User.objects.filter(pk=user.pk).update(is_active=False)
    try:
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

        for token in OutstandingToken.objects.filter(user_id=user.pk):
            BlacklistedToken.objects.get_or_create(token=token)
    except Exception:  # noqa: BLE001 - deactivation already revokes access; blacklisting is best effort
        logger.exception("could not blacklist outstanding tokens for deactivated user %s", user.pk)


class UserViewSet(viewsets.ModelViewSet):
    """
    Admin-only user management API.
    """

    queryset = User.objects.all().order_by("username")
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def destroy(self, request, *args, **kwargs):
        """Remove an operator. Removing one is a stop (the complete revoke), so
        it must never be refused: if a protected reference keeps the row -- a
        MaterialityDecision they decided (decided_by is PROTECT), or any other
        protected ref -- the account is DEACTIVATED and its tokens are revoked
        instead, and the answer says so (lead decision, round 5). Deleting when
        nothing protects the row stays a 204."""
        user = self.get_object()
        try:
            with transaction.atomic():
                self.perform_destroy(user)
        except ProtectedError:
            _deactivate_and_revoke(user)
            return Response(
                {
                    "detail": (
                        f"{user.username} could not be deleted because other records depend on it; "
                        "the account has been deactivated and its tokens revoked instead."
                    ),
                    "deactivated": True,
                },
                status=status.HTTP_200_OK,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def me(self, request):
      """Return the currently authenticated user's profile."""
      serializer = self.get_serializer(request.user)
      return Response(serializer.data)

    @action(detail=True, methods=["patch"])
    def set_role(self, request, pk=None):
        """
        Update a user's role.
        """
        user = self.get_object()
        new_role = request.data.get("role")

        valid_roles = [choice[0] for choice in User.Roles.choices]
        if new_role not in valid_roles:
            return Response(
                {"error": f"Invalid role. Must be one of {valid_roles}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.role = new_role
        user.save(update_fields=["role"])

        return Response(
            {"status": f"Role updated to '{new_role}' for user {user.username}."}
        )

