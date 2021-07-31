
# Create your views here.
from typing import KeysView
from django.db.models.aggregates import Max
from django.http.response import json
from django.shortcuts import render,HttpResponsePermanentRedirect
from functools import reduce
from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth.models import User, auth
from django.contrib.auth import authenticate,login
# from django.contrib.auth.forms import upgradeprofile
from django.http import HttpResponse
from .models import Account, InputData
from .form import MyForm,RegistrationForm,UploadData


from django.shortcuts import get_object_or_404
# Create your views here.
def hello(request):
    data1 = Account.objects.values('username')
    # data = InputData.objects.all().order_by('-id')[:3]
    data = InputData.objects.filter(data_entry__in=InputData.objects.values('username').annotate(Max('data_entry')).values_list('data_entry__max'))
    data2 = InputData.objects.values('username')
    p= json.dumps(list(data1))
    p2= json.dumps(list(data2))
    
    # p = dict(data1)
    # p1 = dict(data2)
    # # print(data1,data2,p2)
    print(p != p2)
    #     # p = dict(u)
    #     for u1 in data2:
    #         print(u)
    # p = data1.union(data2)
    return render(request, 'index.html',{'data' : data,'data1':data1,'data2':data2})

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



# def upgrade(request, *args, **kwargs):
#     if not request.user.is_authenticated:
#         return redirect('login')
#     user_id = kwargs.get("user_id")
#     try:
#         account = Account.objects.get(pk=user_id)
#     except Account.DoesNotExist:
#         return HttpResponse("something went wrong")
#     if account.pk != request.user.pk:
#         return HttpResponse("you cant edit")
#     context = {}
#     if request.POST:
#         form = MyForm(request.POST,instance=request.user)
#         if form.is_valid():
#             form.save()
#             return redirect('upgrade',user_id=account.pk)
#         else:
#             form = MyForm(request.POST,instance=request.user,
#             initial= {
#                 "id" : account.pk,
#                 "is_prouser" : account.is_prouser,
#             }
#             )
#             context['form'] = form
#     else:
#         form = MyForm(request.POST,instance=request.user,
#             initial= {
#                 "id" : account.pk,
#                 "is_prouser" : account.is_prouser,
#             }
#             )
#         context['form'] = form
#     return render(request, 'upgrade.html', context)

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
        