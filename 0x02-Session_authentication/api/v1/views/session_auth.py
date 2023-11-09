#!/usr/bin/env python3
"""handling session auth views"""
from os import getenv
from flask import request, jsonify, abort, make_response
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> str:
    """login route"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400
    user = User.search({"email": email})
    if len(user) == 0:
        return jsonify({"error":  "no user found for this email"}), 404
    for u in user:
        if u.is_valid_password(password):
            from api.v1.app import auth
            sessionid = auth.create_session(u.id)
            session_name = getenv('SESSION_NAME')
            data = make_response(u.to_json())
            data.set_cookie(session_name, sessionid)
            return data
        else:
            return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout() -> str:
    """logging out"""
    from api.v1.app import auth
    destroy = auth.destroy_session(request)
    if destroy is False:
        abort(404)

    return jsonify({}), 200
