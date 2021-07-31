from functools import update_wrapper
from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('',views.hello, name='hello'),
    path('register',views.register, name='register'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('Home', views.Home, name='Home'),
    path('upgrade', views.upgrade, name='upgrade'),
    path('upload',views.upload, name='upload'),
    path('delete/<int:id>/', views.delete, name='delete'),
    path('<int:id>/', views.updatedata, name='update')
    ]