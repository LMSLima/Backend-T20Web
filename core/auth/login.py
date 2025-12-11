from django.db.models import Q
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from ..models.user import User
from ..serializers import UserSerializer  # IMPORTANTE

User = get_user_model()

@api_view(["POST"])
@authentication_classes([])
@permission_classes([])
def LoginUser(request):
    value = request.data.get("email")
    password = request.data.get("password")

    if value and password:
        try:
            user = User.objects.get(Q(username=value) | Q(email=value))
            user_auth = authenticate(username=user.username, password=password)

            if user_auth:
                refresh = RefreshToken.for_user(user_auth)
                access = AccessToken.for_user(user_auth)

                serialized_user = UserSerializer(user_auth).data

                response_data = {
                    "refresh": str(refresh),
                    "access": str(access),
                    "user": serialized_user,
                    "message": "Login realizado com sucesso!"
                }

                return Response(response_data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            pass

    return Response(
        {"message": "Credenciais inválidas!"},
        status=status.HTTP_400_BAD_REQUEST
    )
