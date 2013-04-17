# -*- coding: utf-8 -*-
"""cas_provider.signals -- signal definitions for cas_provider
"""
from django import dispatch


on_cas_collect_histories = dispatch.Signal(providing_args=["for_email"])

on_cas_login = dispatch.Signal(providing_args=["request"])

on_cas_login_success = dispatch.Signal(providing_args=["user", "service"])
on_cas_login_failure = dispatch.Signal(providing_args=["service"])

on_cas_proxy_success = dispatch.Signal(providing_args=["service"])
on_cas_validation_success = dispatch.Signal(providing_args=["service"])
on_cas_validation_failure = dispatch.Signal(providing_args=["code", "message", "service"])

cas_collect_custom_attributes = dispatch.Signal(providing_args=['user'])
