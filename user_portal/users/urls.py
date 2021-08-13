from django.urls import path
from . import views
from .views import *
# from .views import LoginAPI

urlpatterns = [
    path('',views.hello, name='hello'),
    path('register',views.register, name='register'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('Home', views.Home, name='Home'),
    path('upgrade', views.upgrade, name='upgrade'),
    path('upload',views.upload, name='upload'),
    path('delete/<int:id>/', views.delete, name='delete'),
    path('<int:id>/', views.updatedata, name='update'),

# ________________________________________Rest_APIs_________________________________________

    path('registerview', registerview.as_view(), name='registerview'),
    path('loginview', UserLoginView.as_view(), name='loginview'),
    path('userview', userview.as_view(), name='userview'),
    path('logoutview', logoutview.as_view(), name='logoutview'),
    path('SequenceUpload', SequenceUpload.as_view(), name='SequenceUpload'),
    path('UpgradeAccount/<str:pk>', UpgradeAccount.as_view(), name='UpgradeAccount'),
    path('updatedata/<str:pk>', SequencedUpdate.as_view(), name='updatedata'),
    path('dashboard', dashboardview.as_view(), name='dashboard'),
    path('homeview', homeview.as_view(), name='homeview'),
    ]


# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)