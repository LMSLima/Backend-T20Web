from rest_framework.routers import DefaultRouter
from fichas.views import FichaViewSet

router = DefaultRouter()
router.register(r'fichas', FichaViewSet, basename='fichas')

urlpatterns = router.urls
