from django.contrib import admin
from .models import *

# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display = ['id','name','email','password','phone','department']
    
class AdminCredentialsAdmin(admin.ModelAdmin):
    list_display = ['id','email','password','salt']
    
class UserCredentialsAdmin(admin.ModelAdmin):
    list_display = ['id','email','password','salt']
class ReportAdmin(admin.ModelAdmin):
    list_display = ['id','user','report']

class SheetsAdmin(admin.ModelAdmin):
    list_display = ['ObsDateTime','Height','Windspeed','WindDirection','Temperature','Pressure','Humidity','Date']


admin.site.register(User,UserAdmin)
admin.site.register(AdminCredentials,AdminCredentialsAdmin)
admin.site.register(UserCredentials,UserCredentialsAdmin)
admin.site.register(Report,ReportAdmin)
admin.site.register(Sheets,SheetsAdmin)