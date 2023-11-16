#!/usr/bin/env python3

from flask import Flask, jsonify, request, abort, redirect, url_for
from user import User
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def print_text() -> str:
    """print message"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """returns message if user created or already exists"""
    email = request.form.get("email")
    passwd = request.form.get("password")
    try:
        AUTH.register_user(email, passwd)
        return jsonify({"email": "{}".format(email),
                        "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """creating new session"""
    email = request.form.get("email")
    password = request.form.get("password")
    if not(AUTH.valid_login(email, password)):
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({"email": "{}".format(email), "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """if the user exists destroy the session"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect(url_for("print_text"))
    else:
        abort(403)


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """find user"""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": "{}".format(user.email)}), 200
        else:
            abort(403)
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """resetting password"""
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": "{}".format(email),
                        "reset_token": "{}".format(reset_token)}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """updating to new password"""
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, new_password)
    except Exception:
        abort(403)
    return jsonify({"email": "{}".format(email),
                    "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
