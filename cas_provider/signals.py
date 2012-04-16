# -*- coding: utf-8 -*-
"""cas_provider.signals -- signal definitions for cas_provider
"""
from django import dispatch


on_cas_collect_histories = dispatch.Signal(providing_args=["for_email"])

on_cas_login = dispatch.Signal(providing_args=["request"])

cas_collect_custom_attributes = dispatch.Signal(providing_args=['user'])
