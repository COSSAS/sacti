#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
# type: ignore
""" Tests for party """

from sacti import party
from sacti.config import (
    ABORT_MSG,
    AGGREGATOR_ID,
    AGGREGATOR_PORT,
    DAYS,
    HARDCODED_MISP_LAST_EVENTS,
    MISP,
    MISP_KEY,
    MISP_URL,
    PARTIES,
    PARTIES_CONFIG,
    PARTIES_LIST,
)


def test_party_main():
    party_object = party.Party(
        ID=1,
        aggregator_address="127.0.0.1",
        aggregator_port=9181,
        port=8011,
        misp_url=MISP_URL,
        misp_key=MISP_KEY,
    )
