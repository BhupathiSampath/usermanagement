from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.generics import CreateAPIView, UpdateAPIView,RetrieveAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models.aggregates import Max
from rest_framework import serializers, status


class userview(RetrieveAPIView):

    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication

    def get(self, request):
        try:
            account = Account.objects.get(username=request.user)
            status_code = status.HTTP_200_OK
            response = {
                'success': 'true',
                'status code': status_code,
                'message': 'User profile fetched successfully',
                'data': [{
                    'username': account.username,
                    'email': account.email,
                    }]
                }

        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'false',
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'User does not exists',
                'error': str(e)
                }
        return Response(response, status=status_code)

# class userview(APIView):
#     permission_classes = (IsAuthenticated,)
#     authentication_class = JSONWebTokenAuthentication
#     def get(self, request):
#         token = request.COOKIES.get('c_uid')
        
#         return Response(token)
