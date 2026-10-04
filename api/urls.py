from django.urls import path

from .views import login, auth, hello_world

urlpatterns = [
    path('login/', login),
    path('auth/', auth),
    path('hello/', hello_world),
]