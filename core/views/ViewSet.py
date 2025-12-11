from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from core.models import Ficha
from core.serializers import FichaSerializer

class FichaViewSet(ModelViewSet):
    queryset = Ficha.objects.all().order_by("-created_at")
    serializer_class = FichaSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
