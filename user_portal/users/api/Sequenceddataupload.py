from rest_framework import serializers
from rest_framework.fields import ReadOnlyField
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from .registration import UserSerializer


class SequencedSerializer(serializers.ModelSerializer):
    Total_sequenced                 = serializers.IntegerField()
    Sequenced_last_week             = serializers.IntegerField()
    Uploaded_IGIB_SFTP              = serializers.IntegerField()
    Uploaded_NIBMG_DataHub          = serializers.IntegerField()
    Uploaded_GISAID                 = serializers.IntegerField()
    Any_collaboration               = serializers.CharField(required=False)
    # username                        = UserSerializer(read_only=True)
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
        # return Response({"message":"Please enter required fields"})
        return Response(serializer.errors)