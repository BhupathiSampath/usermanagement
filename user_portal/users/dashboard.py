from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from .models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.generics import CreateAPIView, ListAPIView, UpdateAPIView,RetrieveAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models.aggregates import Max

class inputserializers(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = '__all__'


class dashboardview(RetrieveAPIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        QuerySet = InputData.objects.filter(data_entry__in=InputData.objects.values('username').annotate(Max('data_entry')).values_list('data_entry__max'))
        serializer = inputserializers(QuerySet, many =True)
        return Response(serializer.data)