import json
from re import A
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import AllowAny
from django.db.models.aggregates import Max
from users.api.serializers import UserDuplicateSerializer
from django.db.models import Q
class inputserializers(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = '__all__'


class dashboardview(RetrieveAPIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        A = Account.objects.values('username')
        b = InputData.objects.filter().values('username').distinct()
        print(dir(A))
        print(b)
        c = A.difference(b)
        print(c)
        QuerySet = InputData.objects.filter(data_entry__in=InputData.objects.values('username').annotate(Max('data_entry')).values_list('data_entry__max')).order_by('-id').filter(~Q(username="sampath"))
        serializer = inputserializers(QuerySet, many =True)
        serializer1 = UserDuplicateSerializer(c, many=True)
        return Response({"data": serializer.data,"data1":serializer1.data})