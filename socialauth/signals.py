# -*- coding: utf-8 -*-
"""cas_provider.signals -- signal definitions for cas_provider
"""
from django import dispatch


consolidate_google_complete_add_identifer = dispatch.Signal(providing_args=["identifier", "user"])