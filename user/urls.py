from django.urls import path 
from . import views
from .views import *



urlpatterns = [

    #------------ Homepage ---------------#
    #-------------------------------------#
    
    path('',HomeView.as_view(),name='index'),
    


    #------------ Register a user -------------#
    #------------------------------------------#
    
    path('register',RegisterView.as_view(),name='register'),
    


    #------------ Login a user -------------#
    #---------------------------------------#
    
    path('login',MyLoginView.as_view(),name='login'),
    
    #------------ Logout a user-------------#
    #---------------------------------------#
    
    path('logout',UserLogoutView.as_view(),name='logout'),
    


    #------------ Dashboard page -------------#
    #-----------------------------------------#
    
    path('users/<str:username>/dashboard/',DashboardView.as_view(),name='dashboard'),
    
    

    #------------ profile management -------------#
    #-----------------------------------------#
    
    path('users/<str:username>/profile-management/',ProfileManagementView.as_view(),name='profile-management'),
    





    
    #------------ UPDATE USER -------------#
    #-----------------------------------------#
    
    path('users/<str:username>/profile-management/update-user/',UpdateUserView.as_view(),name='update-user'),
    




    
    #------------ DELETE USER -------------#
    #-----------------------------------------#
    
    path('users/<str:username>/profile-management/delete-user/',DeleteUserView.as_view(),name='delete-user'),
    


    path('otp-verify/', OTPVerificationView.as_view(), name='otp-verify'),




    
]











