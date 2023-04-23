from rest_framework.decorators import api_view
from rest_framework.permissions import BasePermission
from rest_framework.authentication import BaseAuthentication
import jwt
from rest_framework.exceptions import AuthenticationFailed
from models import *

JWT_SECRET = 'Shop'


class CustomIsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        auth_header = request.headers.get('Authorization')
        print(auth_header)
        user = User.objects.all()
        active_status = user.is_active
        if not active_status:
            return False
        if auth_header is None:
            return False
        try:
            token = auth_header.split(' ')[1]
            print(token)
        except IndexError:
            return False

        try:
            jwt.decode(token,JWT_SECRET,algorithms=['HS256'])
            return True
        except jwt.exceptions.InvalidTokenError:
            return False


class TokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None
        user = User.objects.all()
        active_status = user.is_active
        if not active_status:
            return None

        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return None

        try:
            data = jwt.decode(token,JWT_SECRET, algorithms=['HS256'])
        except jwt.exceptions.InvalidTokenError:
            raise AuthenticationFailed('Invalid Token')

        return (data['username'],None)