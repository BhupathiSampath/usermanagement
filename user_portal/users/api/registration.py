from rest_framework import serializers
from rest_framework.generics import CreateAPIView, ListAPIView, UpdateAPIView,RetrieveAPIView
from rest_framework.response import Response
from rest_framework import serializers
# Create your views here.
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from users.models import *



class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Account
        fields = ('id','username', 'password', 'password2', 'email',)
        
    def validate(self, value):
        if self.context.get('request').user.is_authenticated:
            raise serializers.ValidationError({"message":"already authenticated"})
        data = self.get_initial()
        username = data.get('username')
        email = data.get('email')
        if Account.objects.filter(username=username).exists():
            raise serializers.ValidationError({"message":"username is already existed"})
        if Account.objects.filter(email=email).exists():
            raise serializers.ValidationError({"message":"email is already existed"})
        if value['password'] != value['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return value

    def create(self, validated_data):
        user = Account.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password'])
        user.save()

        return user


#____________View___________________
class registerview(CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)
    def post(self,request):
        # if request.user.is_authenticated:
        #     return Response({"message":"User is already registered"})
        # if request.method=='POST':
        #     username=request.POST['username']
        #     email=request.POST['email']
        #     # password=request.POST['password']
        #     if Account.objects.filter(username=username).exists():
        #         return Response({"message":"Username is already exists"})
        #     elif Account.objects.filter(email=email).exists():
        #         return Response({"message":"Email is already exists"})
        #     # elif len(password)<4:
        #     #     return Response({"message":"password should > 4 charecters"})
        #     else:
        serializer = self.get_serializer(data=request.data)
        # print(serializer)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"successfully registerd",
            "data":serializer.data})
        else:
            return Response(serializer.errors)