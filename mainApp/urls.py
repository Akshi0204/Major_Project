from django.urls import path
from .views import *
from mainApp import views

urlpatterns = [
    path('', login, name='login'),
    path('login', login, name='login'),
    path('logout', logout, name='logout'),
    path('userLogin', userLogin, name='userLogin'),
    path('adminLogin', adminLogin, name='adminLogin'),
    path('changePassword', changePassword, name='changePassword'),
    path('userHome', userHome, name='userHome'),
    path('adminHome', adminHome, name='adminHome'),
    path('adminHome/addUser', addUser, name='addUser'),
    path('adminHome/manageUsers', manageUsers, name='manageUsers'),
    path('adminHome/manageUsers/update/<int:id>', updateUser, name='updateUser'),
    path('adminHome/manageUsers/delete/<int:id>', deleteUser, name='deleteUser'),
    path('adminHome/updateReport', updateReport, name='updateReport'),
    path('adminHome/upload', views.upload, name='upload'),
    path('adminHome/datasearch', views.datasearch, name='datasearch'),
    path('adminHome/plot', views.plot_view, name='plot_view'),
    path('adminHome/user_activities', userActivities, name='userActivities'),
    path('adminHome/main', chatbot, name='chatbot'),
    path('download', download, name='download'),  
    path('adminHome/download', download_page, name='download_page'),
    path('download-users', download_users, name='download_users'),
    path('adminHome/downloadUsers', download_users_page, name='download_users_page'),  
    
    
]
