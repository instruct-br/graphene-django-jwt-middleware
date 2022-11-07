import jwt
import json
import logging
from . import exceptions
from graphql import GraphQLError
from django.conf import settings

LOGGER = logging.getLogger('graphene-django-jwt-middleware')

HEALTHCHECK_QUERY = "query __ApolloServiceHealthCheck__ { __typename }"


class JWTAuthorizationMiddleware(object):
    def resolve(self, next, root, info, **args):
        request = info.context

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if self.is_healthcheck_query(request._body.decode("utf-8")):
            return next(root, info, **args)

        if token:
            valid_token = self.decode_jwt(token)

            if not isinstance(valid_token, GraphQLError):
                return next(root, info, **args)

            return valid_token

        LOGGER.warning(f'JWT Error: {exceptions.PermissionDenied()}')
        return GraphQLError(exceptions.PermissionDenied())

    def is_healthcheck_query(self, body):
        body = json.loads(body)
        query = body.get("query", "")
        return query == HEALTHCHECK_QUERY

    def decode_jwt(self, token):
        try:
            jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=settings.JWT_ALGORITHMS,
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
