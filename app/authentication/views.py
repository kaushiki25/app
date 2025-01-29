from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.http import JsonResponse
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import RegisterSerializer
from django.contrib.auth.models import User
import random

class RegisterView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=RegisterSerializer,
        responses={201: openapi.Response("OTP sent to email!")}
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']  # Store password

            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['email'] = email
            request.session['username'] = username  # Store username in session
            request.session['password'] = password  # Store password in session

            send_mail('OTP Verification', f'Your OTP is {otp}', 'noreply@example.com', [email])
            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP for verification'),
            },
            required=['otp']
        ),
        responses={201: openapi.Response("User registered successfully!")}
    )
    def post(self, request):
        otp = request.data.get('otp')
        email = request.session.get('email')
        username = request.session.get('username')
        password = request.session.get('password')

        if email and str(otp) == str(request.session.get('otp')):
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                return Response({'message': 'User already registered'}, status=status.HTTP_400_BAD_REQUEST)

            # Create new user with correct username and password
            user = User.objects.create_user(username=username, email=email, password=password)

            return Response({'message': f'User {user.username} registered successfully'}, status=status.HTTP_201_CREATED)

        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

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
            response = JsonResponse({'message': 'Login successful'})
            response.set_cookie('csrftoken', csrf_token, httponly=True, samesite='Lax', secure=True)
            response.set_cookie('auth_token', 'dummyauthtoken', httponly=True, secure=True, samesite='Lax')
            return response

        return JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

class UserDetailsView(APIView):
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={200: openapi.Response("Logout successful")}
    )
    def post(self, request):
        logout(request)
        response = JsonResponse({'message': 'Logout successful'})
        response.delete_cookie('csrftoken')  # Remove CSRF token
        response.delete_cookie('auth_token')  # Remove auth token
        return response
