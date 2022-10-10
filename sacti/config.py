#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""Configuration file."""

import math

################ PROMETHUES SETTINGS #################
DAYS = 30
# If more then MAX_ZEROS zero-valued input the value of the computation
# for that object is set to zero
MAX_ZEROS = 2
RANDOM_RANGE = 10
ABORT_MSG = "ABORT PROTOCOL"

# PARTIES INFO
PARTIES = 3
AGGREGATOR_ID = 0
AGGREGATOR_PORT = 9181

PARTIES_CONFIG = [
    ("1", "127.0.0.1", 8011),
    ("2", "127.0.0.1", 8012),
    ("3", "127.0.0.1", 8013),
    ("4", "127.0.0.1", 8014),
    ("5", "127.0.0.1", 8015),
    ("6", "127.0.0.1", 8016),
]
PARTIES_LIST = list(range(1, PARTIES + 1))

# SHAMIR
INPUT_BIT_LENGTH = 7
POLYNOMIAL_DEGREE = int(math.floor((PARTIES - 1) / 2))
MODULUS = 13003

######################################################

################### CRYPTOGRAPHY  ####################

Hash_Alg = "sha256"
Sig_Alg = "Dilithium2"
Kem_Alg = "Kyber512"

######################################################

################### MISP SETTINGS ####################

MISP = False

MISP_URL = "http://127.0.0.1/"

# The MISP auth key can be found on the MISP web interface under the automation section
MISP_KEY = "ZCjzwjyNf2q4Scylzs8VQ7KZdjd7zqPZuSHH9hJR"  # "3U83QVz4wjlMsE4rUM5c1P8YUqYTasIYq8JHG4pw"

######################################################


################### DEBUG SETTINGS ###################
PKI = True

EVENTS_NUMBER = 2

HARDCODED_MISP_LAST_EVENTS = [
    "test_event_uuid",
    "5f17a0c6-7b04-4f05-9fda-b5d435a8d6a4",
]
HARDCODED_ATTRIBUTE_IDS = ["test_attribute_id_A", "test_attribute_id_B"]

######################################################
