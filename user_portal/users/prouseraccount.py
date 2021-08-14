from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from .models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class UpgradeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["is_prouser"]

class UpgradeAccount(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    serializer_class = UpgradeSerializer
    def post(self,request,pk):
        det = Account.objects.get(id=pk)
        serializer = UpgradeSerializer(instance=det, data=request.data)
        if request.user.is_prouser==True:
            return Response({"message":"Account is already upgraded"})
        if serializer.is_valid():
            serializer.save()
        return Response({"message":"Successfully upgraded"})
