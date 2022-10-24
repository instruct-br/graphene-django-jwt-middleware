import jwt
from . import exceptions
from django.conf import settings


class JWTAuthorizationMiddleware(object):
    def resolve(self, next, root, info, **args):
        request = info.context

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if token:
            self.decode_jwt(token)
            return next(root, info, **args)

        raise exceptions.PermissionDenied()

    def decode_jwt(self, token):
        try:
            jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            raise exceptions.ExpiredSignatureError()
        except jwt.DecodeError:
            raise exceptions.DecodeError()
        except jwt.InvalidTokenError:
            raise exceptions.InvalidTokenError()
