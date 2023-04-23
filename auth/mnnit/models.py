from django.db import models


class User(models.Model):
    username = models.CharField(max_length=255,null=False,unique=True,primary_key=True)
    email = models.CharField(max_length=256,null=False)
    password = models.CharField(max_length=256,null=False)
    is_active = models.BooleanField(default=True)



