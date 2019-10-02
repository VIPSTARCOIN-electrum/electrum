#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from typing import NamedTuple

class Token(NamedTuple):
    contract_addr: str
    bind_addr: str
    name: str
    symbol: str
    decimals: int
    balance: int

