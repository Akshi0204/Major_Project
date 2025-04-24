import datetime
from django.db import models

# Create your models here.

class User(models.Model):
    id=models.AutoField(primary_key=True)
    name=models.CharField(max_length=100)
    email=models.EmailField()
    password=models.CharField(max_length=100)
    phone=models.CharField(max_length=100)
    department=models.CharField(max_length=100)
    def __str__(self):
        return self.name

    
class AdminCredentials(models.Model):
    id=models.AutoField(primary_key=True)
    email = models.EmailField()
    password = models.CharField(max_length=100)
    salt = models.CharField(max_length=100)
    
class UserCredentials(models.Model):
    id=models.AutoField(primary_key=True)
    email = models.EmailField()
    password = models.CharField(max_length=100)
    salt = models.CharField(max_length=100)

class Report(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    report = models.FileField(upload_to='report/')

class Sheets(models.Model):
    ObsDateTime = models.AutoField(primary_key=True)
    Height = models.CharField(max_length=100)
    Windspeed = models.CharField(max_length=100)
    WindDirection = models.CharField(max_length=100)
    Temperature =  models.CharField(max_length=100)
    Pressure =  models.CharField(max_length=100)
    Humidity =  models.CharField(max_length=100)
    Date= models.DateField(null=True)

class UserActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=10)  # 'login' or 'logout'
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f'{self.user.name} - {self.activity_type} - {self.timestamp}'
    