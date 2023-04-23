import datetime

from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.decorators import authentication_classes,permission_classes
from .serializers import UserSerializer
from .models import User
from passlib.hash import pbkdf2_sha256
from django.db.models import Q
import jwt
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import pyotp
from django.core.mail import send_mail
from Ecom.settings import EMAIL_HOST_USER
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

# Create your views here.

JWT_SECRET = 'Shop'

@api_view(['POST'])
@permission_classes([AllowAny])

def signup(request):
    try:
        data = request.data if request.data is not None else {}
        required_fields = set(['username','email','password'])
        if not required_fields.issubset(data.keys()):
            return Response(status=400,data={'error':'Missing Required fields'})


        existing_user = User.objects.filter(Q(username = data['username']) | Q(email=data['email']))
        if existing_user:
            return Response(status=409,data = {'error':'User with same username or email exists'})

        token = jwt.encode({'email': data['email'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)},JWT_SECRET, algorithm='HS256')
        current_site = get_current_site(request)
        relative_link = reverse('activate')
        print(token)
        abs_url = 'http://' + current_site.domain + relative_link + "?token=" + token
        # .decode('utf-8')
        message_body = f"Hi {data['username']},\nPlease use the following link to verify your account:\n{abs_url}"
        send_mail(
            'Verify your account',
            message_body,
            EMAIL_HOST_USER,
            [data['email']],
            fail_silently=False,
        )

        # send_mail(
        #     'OTP Verification',
        #     f'Your OTP is {otp}',
        #     EMAIL_HOST_USER,
        #     [data['email']],
        #     fail_silently=False,
        # )
        password_hash = pbkdf2_sha256.hash(data['password'])
        user = {
            'username':data['username'],
            'email':data['email'],
            'password':str(password_hash),
            'is_active': False,  # save the secret key for OTP verification later
        }
        print(user)
        serializer = UserSerializer(data=user)
        if serializer.is_valid():
            instance = serializer.save()

        return Response(status=status.HTTP_200_OK,data={'message':'OTP Sent to your Email'})
    except Exception as e:
        return Response(status=500,data={'error':str(e)})




@api_view(['GET'])
def activate(request):
    try:
        token = request.query_params.get('token')
        if not token:
            return Response(status=400, data={'error': 'Missing token'})

        # Decode the token and activate the user
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        email = data['email']
        user = User.objects.get(email=email)
        if user.is_active:
            return Response(status=400, data={'error': 'User already activated'})
        user.is_active = True
        user.save()

        return Response(status=status.HTTP_200_OK, data={'statusText': 'User account has been activated.'})
    except Exception as e:
        return Response(status=500, data={'error': str(e)})

@api_view(['POST'])
@permission_classes([AllowAny])

def login(request):
    try:
        data = request.data if request.data is not None else {}
        required_fields = set(['username','email','password'])
        if not required_fields.issubset(data.keys()):
            return Response(status=400,data={'error':'Missing required fields'})

        # a = 'mnnit.ac.in'
        # if a not in data['email']:
        #     return Response(status=400, data={'error': 'Login Using College Email Id'})

        user = User.objects.get(username = data['username'])
        print(user)
        active_status = user.is_active
        print(active_status)
        if not active_status:
            return Response(status=401, data={'error': 'User is not activated. Please Register and activate your account'})

        if user and pbkdf2_sha256.verify(data['password'],user.password):
            token = jwt.encode({'username':user.username,'exp':datetime.datetime.utcnow()+datetime.timedelta(hours=2)},JWT_SECRET)
            return Response(status=200,data={'token':token})
        else:
            return Response(status=401, data={'error':'Invalid Username or Password'})
    except Exception as e:
        return Response(status=500,data={'error':str(e)})

















# def signup(request):
#     try:
#         data = request.data if request.data is not None else {}
#         required_fields = set(['username','email','password'])
#         if not required_fields.issubset(data.keys()):
#             return Response(status=400,data={'error':'Missing Required fields'})
#
#         # a = 'mnnit.ac.in'
#         # if a not in data['email']:
#         #     return Response(status=400, data={'error': 'Login Using College Email Id'})
#         existing_user = User.objects.filter(Q(username = data['username']) | Q(email=data['email']))
#         if existing_user:
#             return Response(status=409,data = {'error':'User with same username or email exists'})
#         password_hash = pbkdf2_sha256.hash(data['password'])
#         user = {
#             'username':data['username'],
#             'email':data['email'],
#             'password':str(password_hash)
#         }
#         serializer = UserSerializer(data=user)
#         if serializer.is_valid():
#             instance = serializer.save()
#         token = jwt.encode({'username':data['username'],'exp':datetime.datetime.utcnow()+datetime.timedelta(hours=2)},JWT_SECRET)
#         return Response(status=status.HTTP_201_CREATED,data={'token':token,'statusText':'User Created'})
#     except Exception as e:
#         return Response(status=500,data={'error':str(e)})
#
# @api_view(['POST'])
# @permission_classes([AllowAny])
#
# def login(request):
#     try:
#         data = request.data if request.data is not None else {}
#         required_fields = set(['username','email','password'])
#         if not required_fields.issubset(data.keys()):
#             return Response(status=400,data={'error':'Missing required fields'})
#
#         # a = 'mnnit.ac.in'
#         # if a not in data['email']:
#         #     return Response(status=400, data={'error': 'Login Using College Email Id'})
#
#         user = User.objects.get(username = data['username'])
#         print(user)
#         if user and pbkdf2_sha256.verify(data['password'],user.password):
#             token = jwt.encode({'username':user.username,'exp':datetime.datetime.utcnow()+datetime.timedelta(hours=2)},JWT_SECRET)
#             return Response(status=200,data={'token':token})
#         else:
#             return Response(status=401, data={'error':'Invalid Username or Password'})
#     except Exception as e:
#         return Response(status=500,data={'error':str(e)})
#
