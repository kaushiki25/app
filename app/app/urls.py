"""
URL configuration for app project.
"""

from django.contrib import admin
from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from authentication.views import RegisterView, VerifyOTPView, LoginView, UserDetailsView, LogoutView

schema_view = get_schema_view(
    openapi.Info(
        title="Authentication API",
        default_version='v1',
        description="API documentation for authentication system",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/register/verify/', VerifyOTPView.as_view(), name='register-verify'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/me/', UserDetailsView.as_view(), name='user-details'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]
