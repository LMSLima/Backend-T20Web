from rest_framework import serializers
from core.models import Ficha

class FichaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ficha
        fields = ["id", "title", "description", "created_at", "updated_at", "owner"]
        read_only_fields = ["id", "created_at", "updated_at", "owner"]
