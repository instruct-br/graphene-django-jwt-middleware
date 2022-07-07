import jwt
from django.conf import settings


class JWTAuthorizationMiddleware(object):
    def resolve(self, next, root, info, **args):
        request = info.context
        is_introspection = "IntrospectionQuery" in str(request._body)

        if is_introspection:
            return next(root, info, **args)

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if token:
            self.decode_jwt(token)
            return next(root, info, **args)

        raise Exception("You do not have permission to perform this action")

    def decode_jwt(self, token):
        try:
            jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            raise Exception("Signature has expired")
        except jwt.DecodeError:
            raise Exception("Error decoding token")
        except jwt.InvalidTokenError:
            raise Exception("Invalid token")
