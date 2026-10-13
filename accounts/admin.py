from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, RoleGrant, rank


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser

    list_display = (
        "username",
        "email",
        "role",
        "is_staff",
        "is_active",
    )
    list_display_links = ("username", "email")
    list_filter = ("role", "is_staff", "is_active")

    fieldsets = (
        (None, {
            "fields": (
                "username",
                "email",
                "password",
                "role",
            )
        }),
        ("Permissions", {
            "fields": (
                "is_active",
                "is_staff",
                "is_superuser",
                "groups",
                "user_permissions",
            )
        }),
        ("Important dates", {
            "fields": ("last_login", "date_joined"),
        }),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "username",
                "email",
                "role",
                "password1",
                "password2",
                "is_staff",
                "is_active",
            ),
        }),
    )

    search_fields = ("username", "email")
    ordering = ("username",)

    readonly_fields = ("last_login", "date_joined")

    def save_model(self, request, obj, form, change):
        # A promotion made here names the signed-in admin who made it (spec-v1,
        # section 35.6, T9b); a demotion records nothing and is never refused.
        before = rank(form.initial.get("role"), form.initial.get("is_superuser")) if change else 0
        obj.grant_role_as(request.user)
        super().save_model(request, obj, form, change)
        if change and rank(obj.role, obj.is_superuser) > before:
            RoleGrant.record(obj, request.user)

