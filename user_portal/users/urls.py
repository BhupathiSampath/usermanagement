from django.contrib.auth import login
from django.urls import path
from . import views
from .views import logoutview, userview
from users.api.registration import registerview
from users.api.login import UserLoginView
from users.api.Sequenceddataupload import SequenceUpload
from users.api.updatesequenced import SequencedUpdate
from users.api.prouseraccount import UpgradeAccount
from users.api.dashboard import dashboardview
from users.api.home import homeview
# from .userview import userview
# from .views import LoginAPI
from rest_framework_jwt.views import refresh_jwt_token
urlpatterns = [
    path('',views.hello, name='hello'),
    path('register',views.register, name='register'),
    path('login', views.login, name='login'),
    path('token-refresh/', refresh_jwt_token),
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