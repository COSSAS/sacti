#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""Messages."""

from dataclasses import dataclass
from math import ceil, log
from typing import Any, Dict, List, Optional, Union

from tno.mpc.encryption_schemes.shamir import ShamirSecretSharingScheme

from sacti.config import INPUT_BIT_LENGTH, PARTIES_LIST


class SightingShare(object):
    """SightingShare object."""

    def __init__(self, uuid: str, value: int, ss: ShamirSecretSharingScheme) -> None:
        """Initialize a new SightingShare object."""
        self.uuid = uuid
        self.bits_shares: Dict[int, CheckShares] = {
            p: CheckShares(self.uuid, [], None, None) for p in PARTIES_LIST
        }
        for i, l in enumerate(self._get_bits(value, INPUT_BIT_LENGTH)):
            for p in PARTIES_LIST:
                self.bits_shares[p].is_bit.append([])

            for b in l:
                onebit_shares = ss.share_secret(b).shares
                for party in PARTIES_LIST:
                    self.bits_shares[party].is_bit[i].append(onebit_shares[party])

    def _get_bits(self, amount: int, bitlength: int) -> List[List[int]]:
        bits = []
        for _ in range(bitlength):
            bit = amount & 1 if amount > 0 else 0
            amount = amount >> 1
            bits.append(bit)  # little-endian
        bits = bits[::-1]  # big-endian
        if bitlength <= 2:
            return [bits]

        return [bits] + self._get_bits(sum(bits), int(ceil(log(bitlength, 2))))

    def __repr__(self) -> str:
        """Represent a SightingShare object."""
        return f"SightingShare: uuid={self.uuid}, bit_shares={self.bits_shares}"


@dataclass
class CheckShares:
    """CheckShares dataclass."""

    uuid: str
    is_bit: List[List[int]]
    belongs: Optional[List[int]]
    is_zero: Optional[int]


@dataclass
class PrometheusEventMessage:
    """PrometheusEventMessage dataclass."""

    uuid: str
    sightings: Dict[str, Union[Dict[Any, Any], CheckShares, int]]
    damage: Union[Dict[int, Any], int, CheckShares]


class PrometheusEvent(object):
    """PrometheusEvent object."""

    def __init__(
        self,
        uuid: str,
        sightings: Dict[Any, Any],
        damage: int,
        ss: ShamirSecretSharingScheme,
    ) -> None:
        """Initialize a new PrometheusEvent."""
        super().__init__()
        self.uuid = uuid
        self.sightings = []

        for attribute_id, amount in sightings.items():
            self.sightings.append(SightingShare(attribute_id, amount, ss))
        self.damage = SightingShare("", damage, ss)

    def __repr__(self) -> str:
        """Represent PrometheusEvent."""
        return f"PrometheusEvent: uuid={self.uuid}, sightings={self.sightings}, damage={self.damage}"

    def generate_msg(
        self,
        parties: Optional[List[int]] = None,
    ) -> Dict[int, Dict[str, PrometheusEventMessage]]:
        """Generate message."""
        if parties is None:
            parties = PARTIES_LIST

        msg: Dict[int, Dict[str, PrometheusEventMessage]] = {p: {} for p in parties}
        for p in parties:
            msg[p] = {
                self.uuid: PrometheusEventMessage(
                    self.uuid,
                    {s.uuid: s.bits_shares[p] for s in self.sightings},
                    self.damage.bits_shares[p],
                )
            }
        return msg
