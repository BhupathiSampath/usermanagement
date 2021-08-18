from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication



class SequencedSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputData
        fields = ["id","username","Total_sequenced","Sequenced_last_week","Uploaded_IGIB_SFTP","Uploaded_NIBMG_DataHub","Uploaded_GISAID","Any_collaboration",]


class SequenceUpload(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def post(self,request):
        serializer = SequencedSerializer(data =request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)