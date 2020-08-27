from django.conf.urls import url
import views
from .decorators import weixin_login_required

app_name = "mp"
urlpatterns = [
    url(r'^ports/', views.ports),
    url(r'^login/$', weixin_login_required(views.LoginView.as_view()), name="login"),
    url(r'^jsapi/config/$', weixin_login_required(views.jsapi_config), name="jsapi_config"),
    url(r'^qr_login/(?P<task_id>[\w-]+)/$', weixin_login_required(views.QRLoginView.as_view()), name="qr-login"),
    url(r'^login_qrcode/', views.LoginQRCodeView.as_view(), name='login-qrcode')
]
