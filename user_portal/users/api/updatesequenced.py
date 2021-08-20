from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from users.models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication



class SequencedSerializer(serializers.ModelSerializer):
    Any_collaboration               = serializers.CharField(required=False)
    class Meta:
        model = InputData
        fields = ["id","username","Total_sequenced","Sequenced_last_week","Uploaded_IGIB_SFTP","Uploaded_NIBMG_DataHub","Uploaded_GISAID","Any_collaboration",]


class SequencedUpdate(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def post(self,request,pk):
        data = InputData.objects.get(id=pk)
        serializer = SequencedSerializer(data=request.data,instance=data)
        print(request.successful_authenticator)
        print(request.user)
        print(dir(request.user.is_prouser))
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Successfully updated"})
        return Response({"message":"Please enter required fields"})