#!/usr/bin/env python3
"""Auth class"""

from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns False - path and excluded_paths"""
        suffix = '/'
        path1 = ""
        path2 = ""

        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True
        while path:
            if path.endswith(suffix):
                path1 = path.rstrip('/')
            else:
                path2 = path + '/'
            if path1 or path2 in excluded_paths:
                return False
            else:
                return True

    def authorization_header(self, request=None) -> str:
        """returns request"""
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None - request"""
        return None

    def session_cookie(self, request=None):
        """returns a cookie value from a request"""
        if request is None:
            return None
        cookie_sesh = getenv('SESSION_NAME', None)
        cookie = request.cookies.get(cookie_sesh, None)
        return cookie
