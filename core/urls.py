from django.urls import path, include
from rest_framework.routers import DefaultRouter
from fichas.views.ficha_viewset import FichaViewSet

# Configura o router para o FichaViewSet
router = DefaultRouter()
router.register(r"fichas", FichaViewSet, basename="fichas")

# Rotas principais
urlpatterns = [
    path("", include(router.urls)),  # inclui todas as rotas do FichaViewSet
]
