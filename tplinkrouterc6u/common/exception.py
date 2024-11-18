class ClientException(Exception):
    pass


class ClientError(ClientException):
    pass


class AuthorizeError(ClientException):
    pass
