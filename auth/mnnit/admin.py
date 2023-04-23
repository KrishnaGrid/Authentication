from django.contrib import admin
from .models import *
# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ['username','email','password','is_active']

admin.site.register(User, UserAdmin)
