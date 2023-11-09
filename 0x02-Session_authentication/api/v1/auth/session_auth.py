#!/usr/bin/env python3
"""inheriting from Auth"""
import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """inherits from Auth"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """creates session ID for a user_id"""
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns a User ID based on a Session ID"""
        if session_id is None or type(session_id) is not str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """returns a User instance based on a cookie value"""
        get_sesh = self.session_cookie(request)
        userid = self.user_id_for_session_id(get_sesh)
        return User.get(userid)

    def destroy_session(self, request=None):
        """deletes the user session / logout"""
        if request is None:
            return False
        sesh_id = self.session_cookie(request)
        if sesh_id is None:
            return False
        user_id = self.user_id_for_session_id(sesh_id)
        if user_id is None:
            return False
        else:
            del self.user_id_for_session[sesh_id]
            return True
