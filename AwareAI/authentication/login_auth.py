from django.contrib import admin
from django.shortcuts import render,redirect
from authentication.models import *

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, logout,update_session_auth_hash
from django.contrib.auth.models import  Group
from django.contrib.auth import logout
from django.contrib import messages
from datetime import datetime, timedelta
import time
from django.core.mail import send_mail
from django.contrib.auth.models import User,auth
from authentication.token import account_activation_token
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.hashers import make_password
from django.template.loader import render_to_string
from django.conf import settings
from authentication.utils import *
from django.contrib.auth import get_user_model
from django.http import JsonResponse,HttpResponse
from authentication.encryption_util import *
from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_required


User = get_user_model()





# Register your models here.



def login(request):
    # if request.user.is_authenticated:
    #     return redirect('/')
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        if not User.objects.filter(email= request.POST.get('email')).exists():
            messages.error(request, "Invalid Email")
            return render(request, 'logins/sign-in.html')
        user = authenticate(username=email,password=password)
        if user is not None :
            auth_login(request,user)
            return redirect("/")
        else:
            messages.error(request, "Invalid Login")
            return render(request, 'logins/sign-in.html')
    else :
        return render(request, 'logins/sign-in.html')


def forgot_password(request):
    if request.method == "POST":
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if User.objects.filter(email= request.POST.get('mail')).exists():
            user=User.objects.get(email=request.POST.get('mail'))
            sender = settings.EMAIL_HOST_USER
            current_site = get_current_site(request)
            mail_subject = 'Change Your  Account Password.'
            message = render_to_string('logins/forget-password-email.html', {
                'user': user,
                'sender': sender,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            to_email = request.POST.getlist('mail')
            e = send_html_mail(mail_subject, message, to_email, sender)
            # messages.success(request,"Check your email")
            return render(request,"logins/reset-pwd-check-email.html")
        else:
            messages.error(request,"email doesn't exist")
    return render(request,'logins/forget-pwd-email.html')


def forgot_password_reset(request,uidb64, token):
    title = "Password_Reset"
    uid = force_text(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)
    if request.method == "POST":
        if user:
            password = request.POST.get('pwd')
            confirm_password = request.POST.get('re_pwd')
            if password == confirm_password:
                user.password = make_password(password=password, salt=None, hasher='default')
                user.save()
                auth_login(request, user)
                # messages.success(request, "Password changed successfully")
                return redirect('/')
            else:
                messages.error(request, "Password and Confirm Password not matched.")
    return render(request, 'logins/forget-pwd.html',{'user': user, 'page_title': title, 'uidb64': uidb64, 'token': token})

def registration(request):
    if request.method == "POST":
        try:
            if User.objects.filter(email=request.POST['email']).exists():
                messages.error(request, 'Email Already Exist')
                return redirect('registration')
            elif User.objects.filter(phone=request.POST['phone']).exists():
                messages.error(request, 'Phone Number Already Exist')
                return redirect('registration')
            else:
                user = User.objects.create_user(username=request.POST.get('email'),first_name=request.POST.get('name'),phone=request.POST.get('phone'),email=request.POST.get('email'))
                sender = settings.EMAIL_HOST_USER
                current_site = get_current_site(request)
                mail_subject = 'Set Your New Password'
                message = render_to_string('logins/acc_active_email.html', {
                    'user': user,
                    'sender': sender,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                })
                to_email = user.email
                e = send_html_mail(mail_subject, message, [to_email], sender)
                message = "Check your email to set the password <br> " + to_email
                return render(request, 'logins/login_mail_success_mes.html', {'message': message})
        except Exception as e:
            messages.error(request,e)
            return render(request, 'logins/sign-up.html')
    else:
        return render(request,'logins/sign-up.html')

def activate(request, uidb64, token):
    title = "Activate"
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if request.method == "POST":
        password = request.POST.get('pwd')
        confirm_password = request.POST.get('cnfmpwd')
        if password==confirm_password:
            user.password = make_password(password=password, salt=None, hasher='default')
            user.save()
            auth_login(request, user)
            #messages.success(request, "Password Added Successfully")
            return redirect('/')
        else:
            messages.error(request, "password and confirm password not matched.")
            return render(request, 'logins/set_password.html',{'user_id': encrypt(user.id), 'title': title,'uidb64': uidb64, 'token': token})
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        message_data= "Thank you for email confirmation. Please set your account password."
        return render(request, 'logins/set_password.html', {'user_id': encrypt(user.id),'title':title,'message_data':message_data,'uidb64':uidb64,'token':token})
    else:
        return HttpResponse('Activation link is invalid!')


@login_required
def userlogout(request):
    logout(request)
    return redirect('login')










