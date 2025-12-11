from rest_framework.permissions import AllowAny
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action

from fichas.models import Ficha
from fichas.serializers import FichaSerializer
class FichaViewSet(viewsets.ModelViewSet):

    queryset = Ficha.objects.all()
    serializer_class = FichaSerializer
    permission_classes = [AllowAny]  # <- ADICIONE ISSO

    @action(detail=True, methods=["get"])
    def export(self, request, pk=None):
        ficha = self.get_object()
        serializer = self.get_serializer(ficha)
        data = serializer.data
        return Response(data)

    @action(detail=False, methods=["post"])
    def import_json(self, request):
        obj = request.data
        FichaSerializer.validate_import_json(obj)
        serializer = self.get_serializer(data=obj)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
