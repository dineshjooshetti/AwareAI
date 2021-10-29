from django.urls import path
from . import views,login_auth,admin

urlpatterns = [
    path('',views.index, name='index'),
    path('login',login_auth.login, name='login'),
    path('registration',login_auth.registration, name='registration'),
    path('forgot_password',login_auth.forgot_password, name='forgot_password'),
    path('forgot_password_reset/<uidb64>/<token>/',login_auth.forgot_password_reset, name='forgot_password_reset'),
    path('activate/<uidb64>/<token>/',login_auth.activate, name='activate'),
    path('userlogout', login_auth.userlogout, name='userlogout'),

    #api
    path('emp_login',views.emp_login.as_view(),name='user_list'),
    path('register',views.register,name='register'),
    ]