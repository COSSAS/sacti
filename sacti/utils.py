#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""Useful functions for the distributed keygen module."""

import logging
from datetime import datetime, timedelta
from sys import stdout
from typing import Any, Callable, Dict, List, Union

from oqs import KeyEncapsulation, Signature

from sacti.config import PKI, Hash_Alg, Kem_Alg, Sig_Alg
from sacti.message import CheckShares, PrometheusEventMessage  # it is used by eval
from sacti.pq_pki_utils import check_signature  # decrypt_aes,
from sacti.pq_pki_utils import check_signed_certificate, random_serial_nr, sign_cert

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"


def generate_pq_keys() -> Dict[str, Union[str, bytes]]:
    """Generate pq keys."""
    # Each party should only do this for herself. The public keys are then distributed via the certificates.
    signer = Signature(Sig_Alg)
    client = KeyEncapsulation(Kem_Alg)
    return {
        "sign_public_key": signer.generate_keypair(),
        "sign_secret_key": signer.export_secret_key(),
        "Sig_Alg": Sig_Alg,
        "Kem_Alg": Kem_Alg,
        "kem_public_key": client.generate_keypair(),
        "kem_secret_key": client.export_secret_key(),
    }


def bitlist_to_int(bitlist: List[int], modulus: int) -> int:
    """Convert bitlist to int."""
    temp = 0
    bitlength = len(bitlist)
    for j in range(bitlength):
        temp = temp + bitlist[j] * (1 << (bitlength - j - 1))
        temp = temp % modulus
    return temp


def decorate_emit(fn: Callable[..., Any]) -> Any:
    """Decorate emitter."""
    # add methods we need to the class
    def new(*args: Any) -> Any:
        levelno = args[0].levelno
        if levelno >= logging.CRITICAL:
            color = "\x1b[31;1m"
        elif levelno >= logging.ERROR:
            color = "\x1b[31;1m"
        elif levelno >= logging.WARNING:
            color = "\x1b[33;1m"
        elif levelno >= logging.INFO:
            color = "\x1b[34;1m"
        elif levelno >= logging.DEBUG:
            color = "\x1b[35;1m *** "
        else:
            color = "\x1b[0m"
        # add colored *** in the beginning of the message
        args[0].msg = f"{color}{args[0].msg}\x1b[0m "

        # new feature i like: bolder each args of message
        args[0].args = tuple("\x1b[1m" + arg + "\x1b[0m" for arg in args[0].args)
        return fn(*args)

    return new


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.propagate = False
sh = logging.StreamHandler(stdout)
sh.setLevel(logging.DEBUG)
sh.setFormatter(logging.Formatter(fmt=FORMAT))
sh.emit = decorate_emit(sh.emit)  # type:ignore

log.addHandler(sh)
