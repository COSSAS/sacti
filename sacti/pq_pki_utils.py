#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""PKI utilities."""

import base64
import datetime
import hashlib
import json
from pathlib import Path
from random import randint
from typing import AbstractSet, Any, Dict, List, Optional, Tuple, Union

import oqs
from cryptography.fernet import Fernet

from sacti.config import PARTIES_LIST, Hash_Alg, Kem_Alg, Sig_Alg

SRC_DIR = str(Path.cwd() / "sacti")


#  General functions
def convert_bytes_to_utf8(byts: bytes) -> str:
    """Change a key of class bytes to utf-8 string."""
    return byts.hex()


def convert_utf8_to_bytes(string: str) -> bytes:
    """Convert a utf-8 string to a key of class bytes."""
    return bytes.fromhex(string)


def json_dump(data: Any, location: str) -> None:
    """
    JSON dump of data to location
    """
    with open(SRC_DIR + "/" + location, "w") as fp:
        token = str(data)
        json.dump(token, fp)
    return None


def json_load(location: str) -> Any:
    """
    JSON load of data to location
    """
    with open(SRC_DIR + "/" + location) as fp:
        token = json.load(fp)
        try:
            loaded_message = eval(token)
        except:
            loaded_message = token
    return loaded_message


#  Cryptographic functions
def encrypt_aes(clear_text: Union[Dict[Any, Any], str], key: bytes) -> bytes:
    """Encrypt with AES encryption."""
    key_hash = digest(Hash_Alg, key)
    secret = base64.b64encode(key_hash)
    f = Fernet(secret)
    message = str(clear_text)
    token = bytes(message, "utf-8")
    cipher_text = f.encrypt(token)
    return cipher_text


def decrypt_aes(cipher_text: bytes, key: bytes) -> bytes:
    """Decrypt with AES decryption."""
    key_hash = digest(Hash_Alg, key)
    assert key_hash is not None, "digest of the key must be valid"
    secret = base64.b64encode(key_hash)
    f = Fernet(secret)
    clear_val = f.decrypt(cipher_text)
    return clear_val


def available_hash_alg() -> AbstractSet[str]:
    """List the available hash algorithms."""
    return hashlib.algorithms_available


def available_sign_alg() -> Any:
    """List the available signature algorithms."""
    return oqs.get_enabled_sig_mechanisms()


def available_kem_alg() -> Any:
    """List the available KEM algorithms."""
    return oqs.get_enabled_KEM_mechanisms()


def mix_key(key1: bytes, key2: bytes) -> bytes:
    """Mixes two keys symmetrically."""
    n1 = len(key1)
    n2 = len(key2)
    key3 = [((int(key1[i]) + int(key2[i])) % 256) for i in range(0, min(n1, n2))]
    return bytes(key3)


def PQ_KEM_encrypt(kemalg: str, public_key: bytes) -> Tuple[Any, Any]:
    """
    Generate a shared secret (a symmetric key) and encrypt it under public_key using the PQ algorithm kemalg.

    Uses OQS library.
    """
    server = oqs.KeyEncapsulation(kemalg)
    ciphertext, shared_secret_server = server.encap_secret(public_key)
    return ciphertext, shared_secret_server


def PQ_KEM_decrypt(ciphertext: bytes, kemalg: str, secret_key: bytes) -> Any:
    """
    Decrypt a ciphertext (containing a symmetric key) with the secret_key of type PQ algorithm kemalg.

    Uses OQS library.
    """
    client = oqs.KeyEncapsulation(kemalg, secret_key)
    shared_secret_client = client.decap_secret(ciphertext)
    return shared_secret_client


def check_signature(
    message: str, message_signature: bytes, cert: Dict[str, str]
) -> Any:
    """Check the signature on a message with the public key from the certificate cert."""
    if True == validate_cert(cert):
        sigalg = cert["signing_alg"]
        verifier = oqs.Signature(sigalg)
        signer_public_key = cert["sign_public_key"]
        is_valid = verifier.verify(
            (json.dumps(str(message))).encode("utf-8"),
            message_signature,
            signer_public_key,
        )
    else:
        return False
    return is_valid


#  Certificate authority functions
def sign_cert(cert: Dict[str, str]) -> Dict[str, str]:
    """
    Sign certificate with the CA (signer) secret key.

    There is no party acting as CA, since we assume a PKI is in place.
    """
    signer_public_keys = {}
    signer_secret_keys = {}
    try:
        signer_public_keys = json_load("PKI/CA_public_key.json")
    except FileNotFoundError:
        pass

    try:
        signer_secret_keys = json_load("PKI/CA_secret_key.json")
    except FileNotFoundError:
        pass

    if (cert["signing_alg"] in signer_public_keys.keys()) & (
        cert["signing_alg"] in signer_secret_keys.keys()
    ):
        signer_secret_key = signer_secret_keys[cert["signing_alg"]]
    else:
        with oqs.Signature(Sig_Alg) as signer:
            signer_public_key = signer.generate_keypair()
            signer_public_keys[cert["signing_alg"]] = signer_public_key
            signer_secret_key = signer.export_secret_key()
            signer_secret_keys[cert["signing_alg"]] = signer_secret_key

            json_dump(signer_public_keys, "PKI/CA_public_key.json")
            json_dump(signer_secret_keys, "PKI/CA_secret_key.json")

    if cert["hash_alg"] not in available_hash_alg():
        print(f"Hash algorithm {0:%s} not available".format(cert["hash_alg"]))
        return cert
    if cert["signing_alg"] not in available_sign_alg():
        print(f"Signing algorithm {0:%s} not available".format(cert["signing_alg"]))
        return cert

    cert["issuer"] = "Trusted certificate authority"
    cert["signature"] = str(None)
    signer = oqs.Signature(cert["signing_alg"], signer_secret_key)
    signature = signer.sign(digest(cert["hash_alg"], str(cert)))
    cert["signature"] = signature
    return cert


def get_signer_public_key(cert: Dict[str, str]) -> Union[Any, bytes, None]:
    """Get the public key of the CA."""
    try:
        signer_public_keys = json_load("PKI/CA_public_key.json")
        sigalg = cert["signing_alg"]
        return signer_public_keys[sigalg]
    except FileNotFoundError:
        print("get_signer_public_key() cannot open CA_public_key.json")
    return None


# Certificate functions
def new_cert() -> Dict[str, str]:
    """Generate a new empty certificate."""
    cert = {
        "country": str(None),
        "email": str(None),
        "kemalg": str(None),
        "kem_public_key": str(None),
        "hash_alg": str(None),
        "ipaddress": str(None),
        "issuer": str(None),
        "name": str(None),
        "not_valid_after": str(None),
        "not_valid_before": str(None),
        "organization": str(None),
        "serial_number": str(None),
        "signature": str(None),
        "signing_alg": str(None),
        "sign_public_key": str(None),
    }
    return cert


def copy_unsigned_cert(cert: Dict[str, str]) -> Dict[str, str]:
    """Copy the certificate without the signature."""
    cert2 = new_cert()
    cert2["name"] = cert["name"]
    cert2["ipaddress"] = cert["ipaddress"]
    cert2["organization"] = cert["organization"]
    cert2["email"] = cert["email"]
    cert2["country"] = cert["country"]
    cert2["not_valid_before"] = cert["not_valid_before"]
    cert2["not_valid_after"] = cert["not_valid_after"]
    cert2["kemalg"] = cert["kemalg"]
    cert2["signing_alg"] = cert["signing_alg"]
    cert2["hash_alg"] = cert["hash_alg"]
    cert2["issuer"] = cert["issuer"]
    cert2["kem_public_key"] = cert["kem_public_key"]
    cert2["sign_public_key"] = cert["sign_public_key"]
    cert2["serial_number"] = cert["serial_number"]
    return cert2


def ip_address() -> str:
    """Get ip-address."""
    return "127.0.0.1"


def random_serial_nr() -> str:
    """Generate a random serial number."""
    z = str(randint(1, 9))
    for _ in range(15):
        z += str(randint(0, 9))
    return z


def digest(hash_alg: str, message: Union[str, bytes]) -> bytes:
    """Provide the digest of the message (string) using the hashing algorithm."""
    h = hashlib.new(hash_alg)
    if isinstance(message, str):
        h.update(message.encode())
    elif isinstance(message, bytes):
        h.update(message)
    else:
        raise RuntimeError("Not digestible")
    return h.digest()


def get_revocation_list() -> List[int]:
    """Fetch the revocation list."""
    revocation_list = []
    try:
        with open("PKI/revocation_list.json", "r") as f:
            revocation_list = list(map(int, f.readlines()))
    except FileNotFoundError:
        pass
    return revocation_list


def add_to_revocation_list(cert: Dict[str, str], revocation_list: List[int]) -> None:
    """Add a certificate to the revocation list."""
    if int(cert["serial_number"]) not in revocation_list:
        revocation_list.append(int(cert["serial_number"]))
    with open("PKI/revocation_list.json", "w") as f:
        for nr in revocation_list:
            f.write("%d \n" % nr)

    return None


def verify_signature(cert: Dict[str, str], signer_public_key: bytes) -> Any:
    """Verify that the certificate is signed with the secret key corresponding to the provided public key."""
    cert2 = copy_unsigned_cert(cert)
    with oqs.Signature(Sig_Alg) as verifier:
        is_valid = verifier.verify(
            digest(cert["hash_alg"], str(cert2)), cert["signature"], signer_public_key
        )
    return is_valid


def validate_cert(cert: Dict[str, str]) -> Any:
    """Check all aspects of the certificate."""
    if cert["hash_alg"] not in available_hash_alg():
        return False
    if cert["signing_alg"] not in available_sign_alg():
        return False
    if cert["kemalg"] not in available_kem_alg():
        return False
    # Validity
    current_time = datetime.datetime.utcnow()
    not_valid_after = datetime.datetime.strptime(
        cert["not_valid_after"], "%d-%m-%y %H:%M:%S"
    )
    not_valid_before = datetime.datetime.strptime(
        cert["not_valid_before"], "%d-%m-%y %H:%M:%S"
    )
    if (current_time < not_valid_before) | (current_time > not_valid_after):
        return False
    # Revocation
    revocation_list = get_revocation_list()
    if int(cert["serial_number"]) in revocation_list:
        return False
    public_key = get_signer_public_key(cert)
    assert public_key is not None, "Public key not found"
    return verify_signature(cert, public_key)


def check_signed_certificate(
    cert: Dict[str, str], cert_b: Dict[str, str]
) -> Union[None, Dict[str, str]]:
    """Check that the submitted certificate cert is correctly signed and properly returned by the signer."""
    revocation_list = get_revocation_list()
    if cert["name"] != cert_b["name"]:
        print("Name changed:", cert["name"], cert_b["name"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["ipaddress"] != cert_b["ipaddress"]:
        print("IP-address changed:", cert["ipaddress"], cert_b["ipaddress"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["organization"] != cert_b["organization"]:
        print("Organization changed:", cert["organization"], cert_b["organization"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["email"] != cert_b["email"]:
        print("E-mail-address changed:", cert["email"], cert_b["email"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["country"] != cert_b["country"]:
        print("Country changed:", cert["country"], cert_b["country"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["not_valid_before"] != cert_b["not_valid_before"]:
        print(
            "Not valid before changed:",
            cert["not_valid_before"],
            cert_b["not_valid_before"],
        )
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["not_valid_after"] != cert_b["not_valid_after"]:
        print(
            "not valid after changed:",
            cert["not_valid_after"],
            cert_b["not_valid_after"],
        )
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["kemalg"] != cert_b["kemalg"]:
        print("Encryption algorithm changed:", cert["kemalg"], cert_b["kemalg"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["signing_alg"] != cert_b["signing_alg"]:
        print("Signing algorithm changed:", cert["signing_alg"], cert_b["signing_alg"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["hash_alg"] != cert_b["hash_alg"]:
        print("Hashing algorithm changed:", cert["hash_alg"], cert_b["hash_alg"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["kem_public_key"] != cert_b["kem_public_key"]:
        print(
            "Encryption key changed:", cert["kem_public_key"], cert_b["kem_public_key"]
        )
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["sign_public_key"] != cert_b["sign_public_key"]:
        print(
            "Signing key changed:", cert["sign_public_key"], cert_b["sign_public_key"]
        )
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif cert["serial_number"] != cert_b["serial_number"]:
        print("Serial number changed:", cert["serial_number"], cert_b["serial_number"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif None == cert_b["issuer"]:
        print("No issuer:", cert_b["issuer"])
        add_to_revocation_list(cert, revocation_list)
        add_to_revocation_list(cert_b, revocation_list)
        return None
    elif False == validate_cert(cert_b):
        print("Certificate validation failed", cert_b)
        return None
    return cert_b


parties = PARTIES_LIST


def main() -> None:
    parties.append(0)  # Aggregator

    print("List of parties")
    print(parties)

    print(f"Cryptographic specifications: {Hash_Alg}, {Sig_Alg}, {Kem_Alg}")

    print("Certificate autority")
    print(
        "\tThe CA is simulated. It is assumed that a PKI is in place before the exchange commences."
    )
    ## Therefore, we can safely assume that the parties honestly simulate a CA.

    print("Generate PQ keys")
    ## Each party should only do this for herself. The public keys are then distributed via the certificates.
    pq_keys = {}
    for p in parties:
        signer = oqs.Signature(Sig_Alg)
        sign_public_key = signer.generate_keypair()
        sign_secret_key = signer.export_secret_key()
        client = oqs.KeyEncapsulation(Kem_Alg)
        kem_public_key = client.generate_keypair()
        kem_secret_key = client.export_secret_key()
        kd = {
            "sign_public_key": sign_public_key,
            "sign_secret_key": sign_secret_key,
            "sigalg": Sig_Alg,
            "kemalg": Kem_Alg,
            "kem_public_key": kem_public_key,
            "kem_secret_key": kem_secret_key,
        }
        pq_keys[p] = kd

    for p in parties:
        json_dump(pq_keys[p], f"PKI/party_{p}/pq_keys.json")
        print(f"Party {p} pq keys saved to PKI/party_{p}/pq_keys.json")

    print("Generate certificates")
    certificates = {}
    for p in parties:
        cert = new_cert()
        cert["name"] = f"Party_{p}"
        cert["ipaddress"] = ip_address()
        cert["organization"] = f"Organization_{p}"
        cert["email"] = cert["name"] + "@" + cert["organization"] + ".eu"
        cert["country"] = "NL"
        cert["not_valid_before"] = datetime.datetime.utcnow().strftime(
            "%d-%m-%y %H:%M:%S"
        )
        cert["not_valid_after"] = (
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).strftime("%d-%m-%y %H:%M:%S")
        cert["kemalg"] = Kem_Alg
        cert["signing_alg"] = Sig_Alg
        cert["hash_alg"] = Hash_Alg
        kem_public_key = pq_keys[p]["kem_public_key"]
        cert["kem_public_key"] = kem_public_key
        sign_public_key = pq_keys[p]["sign_public_key"]
        cert["sign_public_key"] = sign_public_key
        cert["serial_number"] = random_serial_nr()
        # Certificate signing request.
        # The certificate is sent to the CA, who signs it with its secret key.
        cert_b = sign_cert(cert)
        # The party checks whether she received a correctly signed certificate.
        check_outcome = check_signed_certificate(cert, cert_b)
        if check_outcome:
            cert = check_outcome

        certificates[p] = cert

    for p in parties:
        json_dump(certificates[p], f"PKI/party_{p}/certificate.json")
        print(f"Party {p} certificate saved to PKI/party_{p}/certificate.json")

    print("Generate symmetric keys")
    # We have chosen to encrypt all communication between two parties with a single symmetric key.
    # This is not ideal from a security perspective, but saves expensive communication rounds.
    # Alternatively, since the number of messages to exchange is known upfront,
    # it is possible to generate all needed symmetric key pairs at the start of the protocol.

    # Generate and send keys
    key_negotiation_mess = {}
    send_sym_keys = {}
    for p in parties:
        knm: Dict[int, Any] = {}
        ssk: Dict[int, bytes] = {}
        for r in parties:
            if p is not r:
                kem_public_key = certificates[r]["kem_public_key"]
                knm[r], sym_key = PQ_KEM_encrypt(
                    certificates[r]["kemalg"], kem_public_key
                )
                ssk[r] = sym_key
        key_negotiation_mess[p] = knm
        send_sym_keys[p] = ssk
    print(key_negotiation_mess)
    print(send_sym_keys)

    # Obviously, in this local example, there are no messages to send.
    # Otherwise, party p must send key_negotiation_mess[p][r] to party r.

    # Receive and mix keys
    symmetric_keys = {}
    for p in parties:
        sym_keys = {}
        for r in parties:
            if p is not r:
                sym_key1 = send_sym_keys[p][r]
                kem_secret_key2 = pq_keys[p]["kem_secret_key"]
                sym_key2 = PQ_KEM_decrypt(
                    key_negotiation_mess[r][p], pq_keys[p]["kemalg"], kem_secret_key2
                )
                sym_keys[r] = mix_key(sym_key1, sym_key2)
        symmetric_keys[p] = sym_keys

    for p in parties:
        json_dump(symmetric_keys[p], f"PKI/party_{p}/symmetric_keys.json")
        print(f"Party {p} symmetric keys saved to PKI/party_{p}/symmetric_keys.json")


if __name__ == "__main__":
    main()
