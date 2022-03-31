#!/usr/bin/env python3


class PandoraException(Exception):
    pass


class MissingEnv(PandoraException):
    pass


class CreateDirectoryException(PandoraException):
    pass


class ConfigError(PandoraException):
    pass
