from rest_framework import serializers
from core.models import User
from fichas.serializers import FichaSerializer

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    fichas = FichaSerializer(many=True, read_only=True) 

    class Meta:
        model = User
        fields = "__all__"
        depth = 1
