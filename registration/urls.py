from django.conf.urls import url
from django.urls import path,include
from .views import *
from . import views

urlpatterns = [
    url(r'^signup', CreateUser.as_view()),
    url(r'login', Login.as_view()),
    url(r'^update-password', UpdatePassword.as_view()),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete')

]