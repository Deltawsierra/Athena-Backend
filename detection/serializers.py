from rest_framework import serializers
from . import log_upload
from .models import ThreatDetection, CVEClassifyResult


# =========================================================
# DEFENDER — INPUT SERIALIZERS
# =========================================================

class ThreatDetectionScanSerializer(serializers.Serializer):
    """
    Text-based defender scan input.

    ``max_length`` is the log-upload cap in characters; the view also holds the text to it in
    UTF-8 bytes, which is what the engine measures (detection/log_upload.py).
    """
    content = serializers.CharField(max_length=log_upload.LOG_UPLOAD_MAX_BYTES)


class ThreatDetectionUploadSerializer(serializers.Serializer):
    """
    File-based defender scan input.
    """
    uploaded_file = serializers.FileField()


class ThreatDetectionSerializer(serializers.ModelSerializer):
    """
    Minimal read-only serializer for Defender detections.
    Django does not interpret engine results.
    """

    class Meta:
        model = ThreatDetection
        fields = (
            "id",
            "detected",
            "engine_response",
        )
        read_only_fields = fields




# =========================================================
# CVE CLASSIFICATION
# =========================================================

class CVEClassifyInputSerializer(serializers.Serializer):
    """
    Input payload for CVE classification.
    """
    text = serializers.CharField()


class CVEClassifyResultSerializer(serializers.ModelSerializer):
    """
    Read-only CVE classification output.
    """

    class Meta:
        model = CVEClassifyResult
        fields = "__all__"


    

