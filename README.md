# Graphene Django JWT Middleware

This is a [Graphene Django](https://docs.graphene-python.org/projects/django/en/latest/) middleware to check JWT in GraphQL schemas.

## Installing

with pipenv:

```bash
pipenv install graphene-django-jwt-middleware
```

or poetry:

```bash
poetry add graphene-django-jwt-middleware
```

## Usage

In your django `settings.py` file, find `GRAPHENE` configuration and insert at the `MIDDLEWARE` section:

```python
...

GRAPHENE = {
    "SCHEMA": "...",
    'MIDDLEWARE': [
        'graphene_django_jwt_middleware.middleware.JWTAuthorizationMiddleware'
    ]
}

...
```
