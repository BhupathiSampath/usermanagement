from django.db import models
from django.db.models import fields
from django.http import response
from django.http.response import JsonResponse
from rest_framework import serializers
from rest_framework.fields import ReadOnlyField
from rest_framework.response import Response
from . models import Account, InputData



class inputserializers(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    # password1 =serializers.CharField(label='Confirm Password', write_only=True)
    class Meta:
        model = Account
        fields = ["id","username","email","password",]
        extra_kwargs = {
            'password' : {'write_only': True},
            # 'password1': {'write_only': True},
        }
    # def validate_password(self, value):
    #     data = self.get_initial()
    #     password = data.get('password1')
    #     password1 = value
    #     if password != password1:
    #         raise serializers.ValidationError('Passwords must match')
    #     return value

    # def validate_password2(self, value):
    #     data = self.get_initial()
    #     password = data.get('password')
    #     password1 = value
    #     if password != password1:
    #         raise serializers.ValidationError('Passwords must match')
    #     return value

    def create(self, validated_data):
        password = validated_data.pop('password',None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class UpgradeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["is_prouser"]


class SequencedSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = ["id","username","Total_sequenced","Sequenced_last_week","Uploaded_IGIB_SFTP","Uploaded_NIBMG_DataHub","Uploaded_GISAID","Any_collaboration",]


class homeserializer(serializers.ModelSerializer):
    data = UserSerializer(read_only=True ,many =True)
    class Meta:
        model = InputData
        fields = ("id","data")




from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from django.contrib import messages

JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER
from rest_framework.exceptions import APIException

class ServiceUnavailable(APIException):
    status_code = 503
    default_detail = {"message":"A user with this email and password is not not valid."}
    default_code = 'service_unavailable'

class UserLoginSerializer(serializers.Serializer):

    email = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        email = data.get("email", None)
        password = data.get("password", None)
        user = authenticate(email=email, password=password)
        if user is None:
            # self.fail("A user with this email and password is not not valid.")
            raise serializers.ValidationError({"message":"Invalid credentials"}
            )
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