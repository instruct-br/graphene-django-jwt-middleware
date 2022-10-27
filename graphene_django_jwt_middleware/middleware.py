import jwt
from . import exceptions
from django.conf import settings
import logging

class JWTAuthorizationMiddleware(object):
    no_repeat = True

    def resolve(self, next, root, info, **args):
        request = info.context

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if token:
            self.decode_jwt(token)
            return next(root, info, **args)

        logging.warning(exceptions.PermissionDenied())

    def decode_jwt(self, token):
        try:
            jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            if self.no_repeat:
                logging.warning(exceptions.ExpiredSignatureError())
                self.no_repeat = False
        except jwt.DecodeError:
            if self.no_repeat:
                logging.warning(exceptions.DecodeError())     
                self.no_repeat = False
        except jwt.InvalidTokenError:
            if self.no_repeat:
                logging.warning(exceptions.InvalidTokenError())
                self.no_repeat = False