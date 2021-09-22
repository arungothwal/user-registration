from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import PermissionsMixin
import jwt
from django.conf import settings
from rest_framework_jwt.utils import jwt_payload_handler
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, email, password=None):

        if not email:
            raise ValueError('user must have an email')
        if not password:
            raise ValueError('user must have an password')

        email = self.normalize_email(email)
        user = self.model(email=email)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):

        email = self.normalize_email(email)
        user = self.model(email=email)
        user.set_password(password)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser,PermissionsMixin):

    email = models.EmailField(max_length=40, unique=True)
    name = models.CharField(max_length=30,blank=True,null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)


    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


    def __str__(self):
        return self.email

    def create_jwt(self):
        """Function for creating JWT for Authentication Purpose"""
        payload = jwt_payload_handler(self)
        token = jwt.encode(payload, settings.SECRET_KEY)
        auth_token = token.decode('unicode_escape')
        return auth_token

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

