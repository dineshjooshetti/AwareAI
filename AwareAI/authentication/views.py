from django.shortcuts import render,redirect
from .models import *
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout,update_session_auth_hash
from django.contrib.auth.models import  Group
from django.contrib.auth import logout
from django.contrib import messages
from datetime import datetime, timedelta
import time
from django.core.mail import send_mail
from django.contrib.auth.models import User,auth
from .token import account_activation_token
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.hashers import make_password
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
# Create your views here.
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import *
from .models import User
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics
from rest_framework import permissions,decorators
from django.conf import settings
from rest_framework import status
# Create your views here.

def index(request):
    return render(request, 'index.html')

@api_view(['GET',"POST"])
@decorators.permission_classes([permissions.AllowAny])
def register(request):
    if request.method =="POST":
        serializer=UserSerializer(data=request.data)
        if serializer.is_valid():
            #logic
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class emp_login(generics.GenericAPIView):
    permission_classes =[permissions.AllowAny ]
    serializer_class = LoginSerializer
    def post(self,request):
        if request.method == 'POST':
            username = request.data['username']
            password = request.data['password']
            try:
                user = User.objects.get(username=username, password=password)
                serializer = UserSerializer(user)
                data = serializer.data
            except User.DoesNotExist:
                res = {
                    'Error': "Invalid username and password please check once",
                }
                return Response(data=res, status=status.HTTP_400_BAD_REQUEST)
            if user:
                jwt_token = RefreshToken.for_user(user)
                res = {
                    "responseCode": settings.RESPONSE_SUCCESS,
                    "access": str(jwt_token.access_token),
                    "refresh": str(jwt_token)
                }
                return Response(data=[res,data], status=status.HTTP_200_OK)