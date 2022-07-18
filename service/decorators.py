import jwt as jwt
from flask import request, abort

from constants import JWT_SECRET, JWT_ALG


def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        token = request.headers['Authorization']  # Вытащили токен из заголовков
        try:
            jwt.decode(token, JWT_SECRET, algoritms=[JWT_ALG])  # Если токен декодируется, всё норм
        except Exception as e:
            print(f'JWT decode error: {e}')
            abort(401)
        return func(*args, **kwargs)  # key words arguments; Не понимаю, что тут возвращается
    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        token = request.headers['Authorization']
        try:
            data = jwt.decode(token, JWT_SECRET, algoritms=[JWT_ALG])  # Если дату получить удалось, всё норм
        except Exception as e:
            print(f'JWT decode error: {e}')
            abort(401)
        else:
            if data['role'] == 'admin':
                return func(*args, **kwargs)  # key words arguments?urn wrapper
        abort(403)  # Don't have permission, сработает только если role не admin
    return wrapper


