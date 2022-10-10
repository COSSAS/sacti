#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
# type: ignore
""" Tests for aggregator """

from sacti import aggregator
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


def test_aggregator_main():
    aggregator_object = aggregator.Aggregator(MISP_URL, MISP_KEY)
