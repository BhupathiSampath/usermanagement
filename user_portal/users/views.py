from enum import unique
from os import uname
from typing import KeysView
from django.db.models.aggregates import Max
from django.db.models.query import QuerySet
from django.http import response
from django.http.response import JsonResponse, json
from django.shortcuts import render,HttpResponsePermanentRedirect
from functools import reduce
from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth.models import Permission, User, auth
from django.contrib.auth import authenticate,login
# from django.contrib.auth.forms import upgradeprofile
from django.http import HttpResponse, request
from rest_framework import generics
from rest_framework import permissions
from .models import Account, InputData
from .form import MyForm,RegistrationForm,UploadData
from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, ListAPIView, UpdateAPIView,RetrieveAPIView
from rest_framework.response import Response
from rest_framework import serializers, status
from .serializers import inputserializers,UserSerializer,SequencedSerializer, UpgradeSerializer,UserLoginSerializer
from rest_framework.exceptions import AuthenticationFailed
from django.shortcuts import get_object_or_404
# Create your views here.
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
import jwt, datetime
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

class UserLoginView(RetrieveAPIView):

    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        # if request.user.is_authenticated:
        #     return Response({"message":"User is already logged in"})
        if serializer.is_valid():
            token = serializer.data['token']
            response = {
                'success' : 'True',
                'status code' : status.HTTP_200_OK,
                'message': 'User logged in  successfully',
                'token' : serializer.data['token'],
                }
            response = Response()
            response.set_cookie(key='c_uid', value=token,httponly=True,)
            # print(serializer.errors)
            # print(dir(serializer.errors))
            response.data = {
                # 'success' : 'True',
                # 'status code' : status.HTTP_200_OK,
                'message': 'User logged in  successfully',
                # 'token' : serializer.data['token'],
            }
            return response
        else:
            print(serializer.errors)
            return Response(serializer.errors)

class dashboardview(RetrieveAPIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        QuerySet = InputData.objects.filter(data_entry__in=InputData.objects.values('username').annotate(Max('data_entry')).values_list('data_entry__max'))
        serializer = inputserializers(QuerySet, many =True)
        return Response(serializer.data)

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
    
 
class SequenceUpload(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def post(self,request):
        serializer = SequencedSerializer(data =request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

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
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"successfully registerd",
            "data":serializer.data})
        else:
            return Response(serializer.errors)

# class loginview(APIView):
#     def post(self, request):
#         email = request.data['email']
#         password = request.data['password']

#         user = Account.objects.filter(email=email).first()

#         if user is None:
#             raise AuthenticationFailed('User not found')
#         if not user.check_password(password):
#             raise AuthenticationFailed('Invalid password')
#         payload = {
#             'id': user.id,
#             'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=60),
#             'iat': datetime.datetime.utcnow()
#         }
#         token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')

#         response = Response()
#         response.set_cookie(key='jwt', value=token,httponly=True)
#         response.data = {
#             'Message': "Logged in successfully"
#         }
#         return response

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

class logoutview(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def post(self, request):
        response = Response()
        response.delete_cookie('c_uid')
        response.data ={
            "message": "Logged out successfully"
        }
        return response


class homeview(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_class = JSONWebTokenAuthentication
    def get(self, request):
        data = InputData.objects.filter(username=request.user)
        # response = json.dump(data)
        print(request.user)
        serializer = inputserializers(data, many =True)
        return Response(serializer.data)



















def hello(request):
    # data1 = Account.objects.values('username')
    data = InputData.objects.filter(data_entry__in=InputData.objects.values('username').annotate(Max('data_entry')).values_list('data_entry__max'))
    # data2 = InputData.objects.values('username')
    return render(request, 'index.html',{'data' : data})

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = auth.authenticate(email=email,password=password)
        if user is not None:
            auth.login(request,user)
            return redirect('Home')
        else:
            messages.info(request, "invalid credentials")
            return redirect('login')
    else:
        return render(request, 'login.html')

def Home(request):
    data = InputData.objects.filter(username__id=request.user.id)
    return render(request, 'data.html',{'data':data})


def logout(request):
    auth.logout(request)
    return redirect('/')



def upgrade(request):
    if request.method == 'POST':
        form = MyForm(request.POST,instance=request.user)
        if form.is_valid:
            form.save()
            messages.success(request, "you account has been upgraded")
            return redirect('upgrade')

    else:
        form = MyForm(instance=request.user)

        context = {
            'form': form
        }
    return render(request, 'upgrade.html', context)



def register(request):
    context = {}
    if request.POST:
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            email = form.cleaned_data.get('email')
            password1 = form.cleaned_data.get('password1')
            account = authenticate(email=email,password=password1)
            # login(request,account)
            return render(request, 'login.html')
        else:
            context['registration_form'] = form
    else:
        form = RegistrationForm()
        context['registration_form'] = form
    return render(request, 'registration.html', context)

def upload(request):
    form = UploadData()
    if request.method == 'POST':
        print(request.POST)
        form = UploadData(request.POST)
        if form.is_valid():
            form.save()
            return redirect('Home')
        else:
            print("not valid")
    context = {'form': form}
    return render(request, 'data.html',context)

def updatedata(request, id):
    if request.method == 'POST':
        pi = InputData.objects.get(pk=id)
        form = UploadData(request.POST,instance=pi)
        if form.is_valid:
            form.save()
    #         messages.success(request, "you account has been upgraded")
            return redirect('/Home')

    else:
        pi = InputData.objects.get(pk=id)
        form = UploadData(instance=pi)

        context = {
            'form': form
        }
    return render(request, 'update.html', {'id':id})

def delete(request, id):
    if request.method == 'POST':
        pi = InputData.objects.get(pk=id)
        pi.delete()
        return HttpResponsePermanentRedirect('/Home')
        



