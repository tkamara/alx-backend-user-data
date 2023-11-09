#!/usr/bin/env python3
"""inherited class"""

import base64
from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """inherited class"""
    def extract_base64_authorization_header(self, authorization_header: str) \
            -> str:
        """returns the Base64 part of the Authorization
        header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith("Basic "):
            return None
        else:
            ans = authorization_header.strip("Basic ")
            return ans

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64 string
        base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            encoding = base64_authorization_header.encode('utf-8')
            decoding = base64.b64decode(encoding)
            return decoding.decode('utf-8')
        except base64.binascii.Error as error:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        """returns the user email and password from the Base64 decoded value"""
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(":", 1)
        return email, password

    def user_object_from_credentials(self, user_email: str, user_pwd: str)\
            -> TypeVar('User'):
        """ returns the User instance based on his email and password."""
        if type(user_email) is not str or user_email is None:
            return None
        if type(user_pwd) is not str or user_pwd is None:
            return None

        users = User.search({"email": user_email})
        if not users:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user

    def current_user(self, request=None) -> TypeVar('User'):
        """overloads Auth and retrieves the User instance for a request"""
        try:
            header = self.authorization_header(request)
            extracted = self.extract_base64_authorization_header(header)
            decoder = self.decode_base64_authorization_header(extracted)
            mail, pwd = self.extract_user_credentials(decoder)
            user = self.user_object_from_credentials(mail, pwd)
            return user
        except Exception:
            return None
