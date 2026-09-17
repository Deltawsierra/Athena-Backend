from rest_framework.views import APIView
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from django.template.loader import render_to_string
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    HTML = None
    WEASYPRINT_AVAILABLE = False

from .models import AuditLog
from .serializers import AuditLogSerializer
from accounts.permissions import IsAdmin, IsAdminOrAnalyst


class AuditLogPDFView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

    def get(self, request):
        logs = AuditLog.objects.all().order_by("-timestamp")
        html_string = render_to_string(
            "audit/audit_log_pdf.html",
            {"logs": logs},
        )
        pdf = HTML(string=html_string).write_pdf()
        response = HttpResponse(pdf, content_type="application/pdf")
        response["Content-Disposition"] = 'inline; filename="audit_logs.pdf"'
        return response


class AuditLogListAPIView(generics.ListAPIView):
    queryset = AuditLog.objects.all().order_by("-timestamp")
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

