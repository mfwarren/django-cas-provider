from django.conf.urls.defaults import *

from views import *

urlpatterns = patterns('',
    url(r'^login/', login),
    url(r'^socialauth-login/$', socialauth_login),
    url(r'^validate/', validate),
    url(r'^logout/', logout),
)