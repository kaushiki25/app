from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import RegisterSerializer
from django.contrib.auth.models import User


class RegisterView(APIView):
    permission_classes = [AllowAny]  # Allow all users to access this endpoint

    @swagger_auto_schema(
        request_body=RegisterSerializer,
        responses={201: openapi.Response("User registered successfully!")}
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow all users to access this endpoint

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
            },
            required=['username', 'password']
        ),
        responses={200: openapi.Response("Login successful")}
    )
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            csrf_token = get_token(request)
            return JsonResponse({'message': 'Login successful', 'csrf_token': csrf_token}, status=status.HTTP_200_OK)
        return JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)


class UserDetailsView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can access this endpoint

    @swagger_auto_schema(
        responses={
            200: openapi.Response(
                "User details fetched successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="User ID"),
                        'username': openapi.Schema(type=openapi.TYPE_STRING, description="Username"),
                        'email': openapi.Schema(type=openapi.TYPE_STRING, description="User email"),
                    }
                )
            )
        }
    )
    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can log out

    @swagger_auto_schema(
        responses={200: openapi.Response("Logout successful")}
    )
    def post(self, request):
        # Perform logout
        logout(request)
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
