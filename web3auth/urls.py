from django.urls import path

from .views import Web3SignupLoginView

app_name = 'web3auth'

urlpatterns = [
    path('authenticate/', Web3SignupLoginView.as_view(), name='web3auth_authenticate_api'),
]
