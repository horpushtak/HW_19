# `POST /auth` — получает логин и пароль из Body запроса в виде JSON, далее проверяет соотвествие с данными в БД
# (есть ли такой пользователь, такой ли у него пароль)
# и если всё оk — генерит пару access_token и refresh_token и отдает их в виде JSON.
#
# `PUT /auth` — получает refresh_token из Body запроса в виде JSON,
# далее проверяет refresh_token и если он не истек и валиден — генерит пару access_token и refresh_token
# и отдает их в виде JSON.
from flask import request
from flask_restx import Namespace, Resource

from implemented import auth_service

auth_ns = Namespace('auth')

@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get('username')
        password = req_json.get('password')
        if not (username or password):
            return "Не заданы имя и пароль", 401

        tokens = auth_service.generate_tokens(username, password)
        if tokens:
            return tokens
        else:
            return 'Ошибка в запросе', 401

    def put(self):
        req_json = request.json
        refresh_token = req_json.get('refresh_token')  # Принимаем refresh именно в теле запроса, а не в заголовке
        if not refresh_token:
            return "Токен на задан", 401

        tokens = auth_service.approve_refresh_token(refresh_token)  # Перегенерирует пару
        if tokens:
            return tokens
        else:
            return 'Ошибка в запросе', 401
