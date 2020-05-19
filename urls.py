from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.contrib import admin
import as_info.views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('oauth/', include('social_django.urls', namespace='social')),
    path('', as_info.views.index, name='home'),
    path('docs/', as_info.views.docs, name='docs'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('search/', as_info.views.search, name='search'),
]
