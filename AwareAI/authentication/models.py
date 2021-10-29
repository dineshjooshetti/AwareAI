from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class User(AbstractUser):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=30)
    phone = models.BigIntegerField(null=True)
    gender = models.CharField(max_length=30)
    createdby = models.IntegerField(null=True)
    status = models.BooleanField(default=False)
    class Meta:
        db_table = "user"
