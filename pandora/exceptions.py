#!/usr/bin/env python3

from .default import PandoraException


class Unsupported(PandoraException):
    pass


class NoPreview(PandoraException):
    pass


class MissingWorker(PandoraException):
    pass


class TooManyObservables(PandoraException):
    pass
