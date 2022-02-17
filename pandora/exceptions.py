#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .default import PandoraException


class Unsupported(PandoraException):
    pass


class NoPreview(PandoraException):
    pass
