# -*- coding:utf-8 -*- 
# author = 'denishuang'
from __future__ import unicode_literals
from .urls import urlpatterns
from xyz_restful.helper import register_urlpatterns

register_urlpatterns(__package__, urlpatterns)
