from django.urls import path

from web3auth import views

app_name = 'web3auth'

urlpatterns = [
    path('login_api/', views.login_api, name='web3auth_login_api'),
    path('signup_api/', views.signup_api, name='web3auth_signup_api'),
    path('signup/', views.signup_view, name='web3auth_signup'),
]
