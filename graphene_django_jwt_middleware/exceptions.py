class GrapheneDjangoJwtMiddlewareError(Exception):
    default_message = None

    def __init__(self, message=None):
        if message is None:
            message = self.default_message

        super().__init__(message)


class PermissionDenied(GrapheneDjangoJwtMiddlewareError):
    default_message = "You do not have permission to perform this action"


class ExpiredSignatureError(GrapheneDjangoJwtMiddlewareError):
    default_message = "Signature has expired"


class DecodeError(GrapheneDjangoJwtMiddlewareError):
    default_message = "Error decoding token"


class InvalidTokenError(GrapheneDjangoJwtMiddlewareError):
    default_message = "Invalid token"
