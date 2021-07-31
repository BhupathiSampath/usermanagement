from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager
from django.db.models.deletion import SET_DEFAULT
# Create your models here.

class MyAccountManager(BaseUserManager):

    def create_user(self, email, username, password=None):
        if not email:
            raise ValueError("user must have email address")
        if not username:
            raise ValueError("user must have username")
        user = self.model(
            email = self.normalize_email(email),
            username=username,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password):
        user = self.create_user(
            email = self.normalize_email(email),
            username = username,
            password = password,
        )
        user.is_admin =True
        user.is_staff =True
        user.is_superuser =True
        user.save(using=self._db)
        return user

class Account(AbstractBaseUser):
    email               = models.EmailField(verbose_name="email", max_length=60, unique=True)
    username            = models.CharField(max_length=30,unique=True)
    date_joined         = models.DateTimeField(verbose_name ="date joined", auto_now_add=True)
    last_login          = models.DateTimeField(verbose_name ="last login",auto_now=True)
    is_admin            = models.BooleanField(default=False)
    is_active           = models.BooleanField(default=True)
    is_staff            = models.BooleanField(default=False)
    is_superuser        = models.BooleanField(default=False)
    hide_email          = models.BooleanField(default=True)
    is_prouser          = models.BooleanField(default=False)

    objects = MyAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username
    
    def has_perm(self, perms, obj=None):
        return self.is_admin

    def has_module_perms(self, app_Lable):
        return True

class InputData(models.Model):
    data_entry                      = models.DateTimeField(verbose_name ="date joined", auto_now_add=True)
    username                        = models.ForeignKey(Account,verbose_name="username",on_delete=models.CASCADE)
    Total_sequenced                 = models.IntegerField()
    Sequenced_last_week             = models.IntegerField()
    Cumulative_sequenced            = models.IntegerField()
    Uploaded_IGIB_SFTP              = models.IntegerField()
    Uploaded_NIBMG_DataHub          = models.IntegerField()
    Uploaded_GISAID                 = models.IntegerField()
    Any_collaboration               = models.TextField(max_length=200)

    def __string__(self):
        return self.username

    def save(self, *args, **kwargs):
        self.Cumulative_sequenced = self.Total_sequenced +self.Sequenced_last_week
        super(InputData, self).save(*args, **kwargs)

    



