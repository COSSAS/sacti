#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""Prometheus."""

import json
from enum import Enum, auto
from typing import Any, Dict, List, Optional

import oqs
from pymisp import PyMISP  # type:ignore
from tno.mpc.communication.pool import Pool
from tno.mpc.encryption_schemes.shamir import ShamirSecretSharingScheme

from sacti.config import (
    AGGREGATOR_ID,
    MISP,
    MODULUS,
    PARTIES,
    PARTIES_LIST,
    PKI,
    POLYNOMIAL_DEGREE,
    Sig_Alg,
)
from sacti.message import CheckShares, PrometheusEventMessage  # it is used by eval
from sacti.pq_pki_utils import check_signature, decrypt_aes, encrypt_aes, json_load


class ProtocolStage(str, Enum):
    """ProtocolStage to identify messages."""

    EVENT_LIST = auto()
    SHARE_INPUT = auto()
    CHECK_INPUT = auto()
    REVEAL_RANDOM = auto()
    COUNT_ZEROS = auto()
    COMPUTE_AGGREGATION = auto()
    ABORT = 999

    def next(self) -> Any:
        """Get next protocolStage."""
        cls = self.__class__
        members: List[Any] = list(cls)
        index = members.index(self) + 1
        if index >= len(members):
            raise StopIteration("End of ProtocolStage reached")
        return members[index]


class Prometheus(object):
    """Prometheus object."""

    sigalg: str = Sig_Alg
    sign_secret_key: Optional[str] = None
    symmetric_keys: Dict[Any, Any] = {}
    certificates: Dict[int, Dict[str, str]] = {}
    ssss: ShamirSecretSharingScheme = ShamirSecretSharingScheme(
        modulus=MODULUS, number_of_parties=PARTIES, polynomial_degree=POLYNOMIAL_DEGREE
    )
    id: int

    def __init__(self, misp_url: str, misp_key: str, port: int) -> None:
        """Initialize a Prometheus object."""
        super().__init__()
        self.protocol_stage = list(ProtocolStage)[0]
        self.pool = Pool()
        self.pool.add_http_server(port)
        if MISP:
            self.misp = PyMISP(misp_url, misp_key, "json", debug=False)

    def _init_pki(self) -> None:
        """Initialize PKI."""
        self.symmetric_keys = json_load(f"PKI/party_{self.id}/symmetric_keys.json")

        self.certificates = {}
        for party in PARTIES_LIST + [AGGREGATOR_ID]:
            self.certificates[party] = json_load(f"PKI/party_{party}/certificate.json")

        pq_keys = json_load(f"PKI/party_{self.id}/pq_keys.json")
        self.sign_secret_key = pq_keys["sign_secret_key"]

    def encrypt_and_sign_msg(self, message: Any, receiver: int) -> Any:
        """Generate signature for message from self to receiver."""
        if PKI:
            mes_sig = {
                "message": message,
                "signature": self.sign_message(message),
            }
            enc_mes = encrypt_aes(mes_sig, self.symmetric_keys[receiver])
            return enc_mes

        return message

    def decrypt_and_check_msg(self, data: bytes, sender: int) -> Any:
        """Decrypt and check message."""
        if PKI:
            mes_sig_2 = eval(decrypt_aes(data, self.symmetric_keys[sender]))
            sign_valid = check_signature(
                mes_sig_2["message"], mes_sig_2["signature"], self.certificates[sender]
            )
            if not sign_valid:
                raise ValueError("Invalid signature!")
            return mes_sig_2["message"]
        else:
            return data

    def sign_message(
        self,
        message: str,
    ) -> Any:
        """Sign a message (with a PQ) sign algorithm sigalg."""
        signer = oqs.Signature(self.sigalg, self.sign_secret_key)
        print("Sign message", type(message), message)
        signature = signer.sign((json.dumps(str(message))).encode("utf-8"))
        return signature
