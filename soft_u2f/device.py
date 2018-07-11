
import base64
import datetime
import six
import struct
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

from . import crypto_typing as crtyp
from . import persistence


import typing as typ


class Device():

    DEFAULT_CURVE = ec.SECP256R1

    @classmethod
    def _create_certificate(cls) -> typ.Tuple[crtyp.PrivateKeyWithSerialization, bytes]:
        priv_key = ec.generate_private_key(
            cls.DEFAULT_CURVE,
            default_backend(),
        )
        pub_key = priv_key.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        pub_key = pub_key[-65:]
        return priv_key, pub_key

    def get_user_presence_byte(self) -> int:
        return 1

    def __init__(
            self,
            certificate: x509.Certificate,
            private_key: crtyp.PrivateKey,
            persistence: persistence.AbstractCertificatePersistence
    ):
        self.certificate = certificate
        self.private_key = private_key
        self.persistence = persistence
        self.random_source = os.urandom

    def register(self, app_param: bytes, challenge: bytes):
        if len(app_param) != 32 or len(challenge) != 32:
            raise ValueError("Invalid length parameters passed.")
        key_handle = self.random_source(64)

        priv_key, pub_key = self._create_certificate()
        self.persistence.store_key(key_handle, app_param, priv_key)

        sig_data = b'\x00' + app_param + challenge + key_handle + pub_key
        signer = self.private_key.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(sig_data)
        signature = signer.finalize()

        return (
            b'\x05'
            + pub_key
            + bytes([len(key_handle)])
            + key_handle
            + self.certificate.public_bytes(Encoding.DER)
            + signature
        )

    def doAssertion(
        self,
        key_handle: bytes,
        app_param: bytes,
        challenge: bytes,
    ):
        if len(app_param) != 32 or len(challenge) != 32:
            raise ValueError("Invalid length parameters passed.")
        user_presence = bytes([self.get_user_presence_byte()])

        priv_key = self.persistence.get_key(key_handle, app_param)

        counter_val = self.persistence.increment_counter(key_handle)
        counter_bytes = counter_val.to_bytes(4, 'big')

        sig_data = app_param + user_presence + counter_bytes + challenge
        signer = priv_key.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(sig_data)
        signature = signer.finalize()

        return (
            user_presence + counter_bytes + signature
        )
