from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Member(User):
    image = models.ImageField(null=True,blank=True)
    title = models.CharField(max_length=255,null=True,blank=True)
    skills = models.CharField(max_length=500,null=True,blank=True)
    major = models.CharField(max_length=500,null=True,blank=True)



class Profile(models.Model):
    profile_pic = models.ImageField(null=True,blank=True,default='img.png',upload_to='profiles-pictures/')

    user = models.ForeignKey(User,on_delete=models.CASCADE)


