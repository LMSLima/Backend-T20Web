from posixpath import basename
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.routers import DefaultRouter

from core.views import UserViewSet
from fichas.views import FichaViewSet

from core.auth import LoginUser, RegisterUser

router = DefaultRouter()
router.register(r'usuarios', UserViewSet, basename='usuarios')
router.register(r'fichas', FichaViewSet, basename='fichas')
urlpatterns = [
    path('admin/', admin.site.urls),
    # OpenAPI 3
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path(
        'api/swagger/',
        SpectacularSwaggerView.as_view(url_name='schema'),
        name='swagger-ui',
    ),
    path(
        'api/redoc/',
        SpectacularRedocView.as_view(url_name='schema'),
        name='redoc',
    ),
    # API
    path('api/', include(router.urls)),
    path("api/auth/register/", RegisterUser, name="register"),
    path("api/auth/login/", LoginUser, name="login"),
    path('api/auth/', include('core.urls')),
    path("api/", include("core.urls")),
    path("api/", include("fichas.urls")),
]
