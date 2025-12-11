"""
Database models.
"""

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, username, email, password=None, **extra_fields):
        """Create, save and return a new user."""
        if not username:
            raise ValueError("Users must have a username.")
        if not email:
            raise ValueError("Users must have an email address.")

        email = self.normalize_email(email)

        user = self.model(
            username=username,
            email=email,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """Create and return a new superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """User model in the system."""

    passage_id = models.CharField(max_length=255, unique=False, verbose_name=_('passage_id'), help_text=_('Passage ID'))
    email = models.EmailField(max_length=255, unique=True, verbose_name=_('email'), help_text=_('Email'))
    name = models.CharField(max_length=255, blank=True, null=True, verbose_name=_('name'), help_text=_('Username'))
    username = models.CharField(max_length=255, unique=True, default='user')
    is_active = models.BooleanField(
        default=True, verbose_name=_('Usuário está ativo'), help_text=_('Indica que este usuário está ativo.')
    )
    is_staff = models.BooleanField(
        default=False,
        verbose_name=_('Usuário é da equipe'),
        help_text=_('Indica que este usuário pode acessar o Admin.'),
    )

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]
    EMAIL_FIELD = "email"

    class Meta:
        """Meta options for the model."""

        verbose_name = 'Usuário'
        verbose_name_plural = 'Usuários'
