#!/usr/bin/env python3
"""defining hased password"""

from user import User, Base
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import Union


def _hash_password(password: str) -> bytes:
    """returned bytes is a salted hash of the input password
    """
    passwd_bytes = password.encode('utf-8')
    # generating salt
    salt = bcrypt.gensalt()
    # getting salted hash
    hashed = bcrypt.hashpw(passwd_bytes, salt)
    return hashed


def _generate_uuid() -> str:
    """returns a uuid"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """hashing new users"""
        try:
            users = self._db.find_user_by(email=email)
            if users:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed_pwd = _hash_password(password)
            return self._db.add_user(email, hashed_pwd)

    def valid_login(self, email: str, password: str) -> bool:
        """checks if email matches password"""
        try:
            users = self._db.find_user_by(email=email)
            if users:
                if bcrypt.checkpw(password.encode('utf-8'),
                                  users.hashed_password):
                    return True
                else:
                    return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """returns session ID as string"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                user.session_id = _generate_uuid()
                self._db.update_user(user_id=user.id,
                                     session_id=user.session_id)
                return str(user.session_id)
        except NoResultFound:
            return

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """returns user from session ID"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """updates user's session ID to none"""
        try:
            self._db.update_user(user_id=user.id, session_id=None)
            return None
        except Exception:
            return

    def get_reset_password_token(self, email: str) -> str:
        """dealing with reset token"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                user.reset_token = _generate_uuid()
                self._db.update_user(user_id=user.id,
                                     reset_token=user.reset_token)
                return str(user.reset_token)
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """updating to new password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            if user:
                passwd = _hash_password(password)
                self._db.update_user(user_id=user.id,
                                     hashed_password=passwd,
                                     reset_token=None)
        except NoResultFound:
            raise ValueError
