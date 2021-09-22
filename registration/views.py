from .models import MyUser
from .serializers import MyUserSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import send_email
from rest_framework import generics, status, views, permissions
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny, IsAuthenticatedOrReadOnly

# Create your views here.

"""User signup """


class CreateUser(APIView):
    def post(self, request):
        try:
            params = request.data
            serializer = MyUserSerializer(data=params)
            if serializer.is_valid(raise_exception=True):
                user = serializer.save()
                user.set_password(params['password'])
                user.is_active = True
                user.save()
            return Response({'message': "signup succesfully"}, status=status.HTTP_200_OK,
                            content_type='application/json')
        except Exception as e:
            return Response({'message': 'something went wrong'}, status=status.HTTP_400_BAD_REQUEST)


"""user login"""


class Login(APIView):

    def post(self, request):
        try:
            params = request.data
            user_exist = MyUser.objects.get(email=params['email'])
            print(user_exist, 'user_exist')

            if not user_exist:
                return Response({"message": "Signup First"}, status=400)
            user = authenticate(email=params['email'], password=params['password'])
            if user:
                serializer = MyUserSerializer(user)
                login(request, user)
                return Response(
                    {"message": "Logged in successfully.", "data": serializer.data, "token": user.create_jwt()},
                    status=status.HTTP_200_OK)
            else:
                return Response({"message": "Please enter correct credentials"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({"message": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST)


"""update password"""


class UpdatePassword(APIView):
    permission_classes = (IsAuthenticated,)

    def patch(self, request):
        try:
            user_email = request.user.email
            params = request.data
            current_password = params['current_password']
            new_password = params['new_password']
            confirm_new_password = params['confirm_new_password']

            if not new_password == confirm_new_password:
                return Response({"message": "New password and Confirm password is not matching."},
                                status=status.HTTP_400_BAD_REQUEST)
            user = authenticate(email=user_email, password=current_password)
            if user is None:
                return Response({"message": "Current password dosen't match with old password"},
                                status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password updated successfuly"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': 'success', "message": "Something went wrong"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


"""forgot password"""


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            email = request.data.get('email', '')
            if MyUser.objects.filter(email=email).exists():
                user = MyUser.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=request).domain
                relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
                absurl = 'http://' + current_site + relativeLink
                email_body = 'Hello, \n Use link below to reset your password  \n' + \
                             absurl
                data = {'email_body': email_body, 'to_email': user.email,
                        'email_subject': 'Reset your passsword'}
                send_email(data)
                return Response({'success': 'We have sent you a link to reset your password'},
                                status=status.HTTP_200_OK)
            else:
                return Response({'failed': 'Signup First'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': 'Failed', "message": "Something went wrong"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


"""verify token"""


class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = MyUser.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'success': True, 'message': 'credentials valid', 'uidb64': uidb64, 'token': token},
                                status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': 'Token is not valid, please request a new one'},
                            status=status.HTTP_400_BAD_REQUEST)


""" reset password"""


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)
