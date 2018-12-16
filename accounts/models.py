from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    # add additional fields in here
    name = models.CharField(max_length=100, null=True)
    rollno = models.CharField(max_length=9, null=True)
    emailp = models.EmailField(null=True)
    emaili = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=10, null=True)

    def __str__(self):
        return self.name + " | " + self.username
