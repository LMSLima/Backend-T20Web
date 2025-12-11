from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from core.models import User
from core.serializers import UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken  # se usar JWT

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.create_user(
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password'],
            name=serializer.validated_data.get('name', '')
        )

        # Opcional: gerar token JWT se estiver usando SimpleJWT
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response(
            {
                "user": UserSerializer(user).data,
                "token": access_token  # assim o frontend já pode logar automático
            },
            status=status.HTTP_201_CREATED
        )
