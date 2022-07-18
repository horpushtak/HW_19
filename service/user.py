import base64
import hashlib
import hmac

from dao.model.user import User
from dao.user import UserDAO
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_data):
        user_data['password'] = self.get_password_hash(user_data['password'])
        return self.dao.create(user_data)

    def update(self, user_data):
        self.dao.update(user_data)
        return self.dao

    def delete(self, uid):
        self.dao.delete(uid)

    def get_password_hash(self, password):
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))
    # base64 нужен, чтобы положить в базу, где всё лежит в строке

    def compare_passwords(self, password, password_hash):
        """Декодируем хэшированный пароль и сравниваем с тем,
         что прислал пользователь, оборачивая в хэш.
        Cравнивает циферки, тут надо аккуратно"""
        return hmac.compare_digest(base64.b64decode(password_hash), base64.b64decode(self.get_password_hash(password)))


