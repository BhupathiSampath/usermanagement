
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework import serializers, status
from .serializers import UserLoginSerializer
from django.shortcuts import get_object_or_404
# Create your views here.
from rest_framework.permissions import AllowAny


from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from django.contrib import messages
from users.models import *

JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER

class UserLoginSerializer(serializers.Serializer):
    permission_classes = (AllowAny,)
    email = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)
    
    def validate(self, data):
        
        if self.context.get('request').user.is_authenticated:
            raise serializers.ValidationError({"message":"already authenticated"})
        
        email = data.get("email", None)
        password = data.get("password", None)
        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError({"message":"Invalid credentials"})
        try:
            payload = JWT_PAYLOAD_HANDLER(user)
            jwt_token = JWT_ENCODE_HANDLER(payload)
            update_last_login(None, user)
        except Account.DoesNotExist:
            raise serializers.ValidationError({"message":"Invalid credentials"})
        return {
            'email':user.email,
            'token': jwt_token
        }



class UserLoginView(RetrieveAPIView):

    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
    
        # if request.user.is_authenticated:
            
        #     return Response({"message":"User is already logged in"})
        if serializer.is_valid():
            token = serializer.data['token']
            response = {
                'success' : 'True',
                'status code' : status.HTTP_200_OK,
                'message': 'User logged in  successfully',
                'token' : serializer.data['token'],
                }
            response = Response()
            response.set_cookie(key='c_uid', value=token,httponly=True,)
            # print(serializer.errors)
            # print(dir(serializer.errors))
            response.data = {
                # 'success' : 'True',
                # 'status code' : status.HTTP_200_OK,
                'message': 'User logged in  successfully',
                # 'token' : serializer.data['token'],
            }
            return response
        print(serializer.errors['message'][0])
        return Response({'message': serializer.errors['message'][0]})