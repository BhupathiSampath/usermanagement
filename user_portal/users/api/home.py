from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.permissions import IsAuthenticated
# from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from users.auth import JSONWebTokenAuthentication
from rest_framework.generics import CreateAPIView, ListAPIView, UpdateAPIView,RetrieveAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models.aggregates import Max
from rest_framework import serializers, status


class inputserializers(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = '__all__'

        
class homeview(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def get(self, request):
        if request.user is None:
            return Response("SSS")
        data = InputData.objects.filter(username=request.user)
        # response = json.dump(data)
        print(request.user)
        serializer = inputserializers(data, many =True)
        return Response(serializer.data)
