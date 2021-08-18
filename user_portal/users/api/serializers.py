# from typing_extensions import Required
from django.db import models
from django.db.models import fields
from django.http import response
from django.http.response import JsonResponse
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.fields import ReadOnlyField
from rest_framework.response import Response
from rest_framework.validators import UniqueValidator
from users.models import Account, InputData



class inputserializers(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = '__all__'

class UserDuplicateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = [
            'username',
            'email',
        ]


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Account
        fields = ('id','username', 'password', 'password2', 'email',)
        
    def validate(self, value):
        data = self.get_initial()
        username = data.get('username')
        email = data.get('email')
        if self.context.get('request').user.is_authenticated:
            raise serializers.ValidationError({"message":"already authenticated"})
        if self.context.get('request').user.is_authenticated:
            raise serializers.ValidationError({"message":"already authenticated"})
        if Account.objects.filter(username=username).exists():
            raise serializers.ValidationError({"message":"username is already existed"})
        if Account.objects.filter(email=email).exists():
            raise serializers.ValidationError({"message":"email is already existed"})
        if value['password'] != value['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return value

    def create(self, validated_data):
        user = Account.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password'])
        user.save()

        return user

class UpgradeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["is_prouser"]
class SequencedSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = ["id","username","Total_sequenced","Sequenced_last_week","Uploaded_IGIB_SFTP","Uploaded_NIBMG_DataHub","Uploaded_GISAID","Any_collaboration",]




from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from django.contrib import messages

JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER

class UserLoginSerializer(serializers.Serializer):

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



