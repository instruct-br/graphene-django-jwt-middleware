import logging
import jwt
from . import exceptions
from graphql import GraphQLError
from django.conf import settings

LOGGER = logging.getLogger('graphene-django-jwt-middleware')


class JWTAuthorizationMiddleware(object):
    def resolve(self, next, root, info, **args):
        request = info.context

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if token:
            valid_token = self.decode_jwt(token)

            if not isinstance(valid_token, GraphQLError):
                return next(root, info, **args)

            return valid_token

        LOGGER.warning(f'JWT Error: {exceptions.PermissionDenied()}')
        return GraphQLError(exceptions.PermissionDenied())

    def decode_jwt(self, token):
        try:
            jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            LOGGER.warning(f'JWT Error: {exceptions.ExpiredSignatureError()}')
            return GraphQLError(exceptions.ExpiredSignatureError())
        except jwt.DecodeError:
            LOGGER.warning(f'JWT Error: {exceptions.DecodeError()}')
            return GraphQLError(exceptions.DecodeError())
        except jwt.InvalidTokenError:
            LOGGER.warning(f'JWT Error: {exceptions.InvalidTokenError()}')
            return GraphQLError(exceptions.InvalidTokenError())
