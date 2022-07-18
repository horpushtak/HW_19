import calendar
import datetime
from constants import JWT_SECRET, JWT_ALG
import jwt

from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):  # Принимает на инициализацию сервис Пользователь
        self.user_service = user_service

    def generate_tokens(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)

        if not user:
            return False  # Забыл, как работает Exception, посмотреть
        # В сервисе лучше не абортить, а try-ить выше, потому что ... ?
        # Желательно рейзить свои ошибки потому что ... ?
        # В итоге просто False................................................................хм

        if not is_refresh:  # То есть не True, если я не запутался
            if not self.user_service.compare_passwords(password, user.password):  # Второй пришёл с запроса, но он же
                # тогда должен быть первым: password, а уж потом user.password
                # upd: да, так в итоге и сделали
                return False

        data = {
            "username": user.username,
            "role": user.role
        }

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())  # Дописали в дату ещё значение exp
        asses_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALG)

        day30 = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        data['exp'] = calendar.timegm(day30.timetuple())
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALG)

        return {'asses_token': asses_token, 'refresh_token': refresh_token}

    def approve_refresh_token(self, refresh_token):
        data = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALG])  # в decode только во мн. ч.
        username = data['username']  # Вытаскиваем имя
        user = self.user_service.get_by_username(username)  # Проверяем, есть ли такой с хорошим токеном

        if not user:
            return False
