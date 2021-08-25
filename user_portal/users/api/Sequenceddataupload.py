from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class SequencedSerializer(serializers.ModelSerializer):
    # Total_sequenced                 = serializers.IntegerField()
    # Sequenced_last_week             = serializers.IntegerField()
    # Uploaded_IGIB_SFTP              = serializers.IntegerField()
    # Uploaded_NIBMG_DataHub          = serializers.IntegerField()
    # Uploaded_GISAID                 = serializers.IntegerField()
    # Any_collaboration               = serializers.CharField(required=False)
    # username                        = UserSerializer(read_only=True)
    class Meta:
        model = InputData
        fields = ["id","username","Total_sequenced","Sequenced_last_week","Uploaded_IGIB_SFTP","Uploaded_NIBMG_DataHub","Uploaded_GISAID","Any_collaboration",]
    
    
    def validate(self, attrs):
        data = self.get_initial()
        Total_sequenced = data.get('Total_sequenced')
        Uploaded_GISAID = data.get('Uploaded_GISAID')
        Sequenced_last_week = data.get('Sequenced_last_week')
        Uploaded_IGIB_SFTP = data.get('Uploaded_IGIB_SFTP')
        Uploaded_NIBMG_DataHub = data.get('Uploaded_NIBMG_DataHub')
        username = data.get('username')
        if username is None:
            raise serializers.ValidationError({"message":"username is required field"})
        if Total_sequenced is None:
            raise serializers.ValidationError({"message":"Total_sequenced is required field"})
        if Sequenced_last_week is None:
            raise serializers.ValidationError({"message":"Sequenced_last_week is required field"})
        if Uploaded_IGIB_SFTP is None:
            raise serializers.ValidationError({"message":"Uploaded_IGIB_SFTP is required field"})
        if Uploaded_NIBMG_DataHub is None:
            raise serializers.ValidationError({"message":"Uploaded_NIBMG_DataHub is required field"})
        if Uploaded_GISAID is None:
            raise serializers.ValidationError({"message":"Uploaded_GISAID is required field"})
        return super().validate(attrs)
class SequenceUpload(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def post(self,request):
        serializer = SequencedSerializer(data =request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        # return Response({"message":"Please enter required fields"})
        return Response({'message': serializer.errors['message'][0]})