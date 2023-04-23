from django.urls import path
# from views import ProductView
from .import views
from .import auth


urlpatterns = [
    # path('v1/marketplace/products', views.products, name='product'),
    path('signup/',auth.signup,name = 'signup'),
    path('activate/',auth.activate,name = 'activate'),
    path('login/',auth.login,name = 'login'),
    path('home/',views.home,name = 'home'),
]