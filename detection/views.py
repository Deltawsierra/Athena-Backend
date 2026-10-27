from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status, generics
from django.http import HttpResponse 

from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

from . import log_upload
from .models import ThreatDetection, CVEClassifyResult
from .serializers import (
    ThreatDetectionScanSerializer,
    ThreatDetectionUploadSerializer,
    CVEClassifyInputSerializer,
    CVEClassifyResultSerializer,
    ThreatDetectionSerializer
)

from .utils import generate_cve_pdf 


# =========================================================
# DEFENDER (BLUE TEAM)
# =========================================================

class DefenderTextScanAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ThreatDetectionScanSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        content = serializer.validated_data["content"]
        client = CyberEngineClient.from_settings()

        try:
            engine_response = client.defend_log_text(content)
        except EngineError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        detection = ThreatDetection.objects.create(
            file_name="text_input",
            detected=bool(engine_response.get("alerts")),
            engine_response=engine_response,
        )

        return Response(
            {
                "id": detection.id,
                "detected": detection.detected,
                "engine_response": detection.engine_response,
            },
            status=status.HTTP_201_CREATED,
        )


class DefenderFileScanAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # A body that declares itself over the cap is refused before request.data
        # parses it, and a file is read only within the cap (detection/log_upload.py).
        log_upload.check_declared_length(request)
        serializer = ThreatDetectionUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["uploaded_file"]
        content = log_upload.read_log_text(uploaded_file)

        client = CyberEngineClient.from_settings()

        try:
            engine_response = client.defend_log_text(content)
        except EngineError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        detection = ThreatDetection.objects.create(
            file_name=uploaded_file.name,
            detected=bool(engine_response.get("alerts")),
            engine_response=engine_response,
        )

        return Response(
            {
                "id": detection.id,
                "detected": detection.detected,
                "engine_response": detection.engine_response,
            },
            status=status.HTTP_201_CREATED,
        )


class DefenderListAPIView(generics.ListAPIView):
    queryset = ThreatDetection.objects.all()
    serializer_class = ThreatDetectionSerializer


class DefenderDetailAPIView(generics.RetrieveAPIView):
    queryset = ThreatDetection.objects.all()
    serializer_class = ThreatDetectionSerializer


# =========================================================
# CVE CLASSIFICATION (ENGINE-BACKED)
# =========================================================

class CVEClassifyAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CVEClassifyInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        text = serializer.validated_data["text"]
        client = CyberEngineClient.from_settings()

        try:
            engine_response = client.classify_cve(text)
        except EngineError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        result = CVEClassifyResult.objects.create(
            input_text=text,
            engine_response=engine_response,
        )

        return Response(
            CVEClassifyResultSerializer(result).data,
            status=status.HTTP_201_CREATED,
        )


class CVEClassifyListAPIView(ListAPIView):
    queryset = CVEClassifyResult.objects.all()
    serializer_class = CVEClassifyResultSerializer
    permission_classes = [IsAuthenticated]


class CVEClassifyDetailAPIView(RetrieveAPIView):
    queryset = CVEClassifyResult.objects.all()
    serializer_class = CVEClassifyResultSerializer
    permission_classes = [IsAuthenticated]


class CVEPDFAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        # An id that does not exist raised DoesNotExist and became a 500.
        cve = get_object_or_404(CVEClassifyResult, pk=pk)
        filename, pdf_bytes = generate_cve_pdf(cve)

        response = HttpResponse(
               pdf_bytes,
               content_type="application/pdf",
)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response



class CVEEmailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        """
        Email a CVE classification.

        The success path of this method was empty, so it returned None and
        Django raised on every well-formed request. It is not implemented, and
        now says so instead of failing as a server error.
        """
        recipient = request.data.get("recipient_email")
        if not recipient:
            return Response(
                {"error": "recipient_email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {"error": "Emailing a CVE classification is not implemented yet."},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

        


   




