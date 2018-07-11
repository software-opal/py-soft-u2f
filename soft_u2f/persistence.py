import abc
import typing as typ

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from . import crypto_typing as crtyp


class AbstractCertificatePersistence(abc.ABC):
    """
    Implemented by classes that store the generated keys for a site.
    """

    @staticmethod
    def key_to_bytes(
            key: crtyp.PrivateKeyWithSerialization,
            password: typ.Optional[bytes]=None,
    ) -> bytes:
        enc_alg = serialization.NoEncryption()
        if password:
            enc_alg = serialization.BestAvailableEncryption(password)
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg,
        )

    @staticmethod
    def bytes_to_key(
            key_data: bytes,
            password: typ.Optional[bytes]=None,
    ) -> crtyp.PrivateKeyWithSerialization:
        return serialization.load_der_private_key(
            data=key_data,
            password=password,
            backend=default_backend()
        )

    @abc.abstractmethod
    def get_counter(self, key_handle: bytes) -> int:
        """
        Get the current counter for the key.

        This can be implemented as a global counter or a per-key counter. The
        only requirement is that it is a monatonically increasing number.

        May raise a KeyError if the key is not found
        """
        pass

    @abc.abstractmethod
    def increment_counter(self, key_handle: bytes) -> int:
        """
        Increment the current counter for the key.

        This can be implemented as a global counter or a per-key counter. The
        only requirement is that it is a monatonically increasing number.

        May raise a KeyError if the key is not found
        """
        pass

    @abc.abstractmethod
    def get_key(self, key_handle: bytes, app_param: bytes) -> crtyp.PrivateKeyWithSerialization:
        """
        Get the given key using the key handle; and verifying to app param.

        Raises a KeyError if the key is not found and a ValueError if the app
        param doesn't match
        """
        pass

    @abc.abstractmethod
    def store_key(self,
                  key_handle: bytes,
                  app_param: bytes,
                  private_key: crtyp.PrivateKeyWithSerialization
                  ):
        pass


class InMemoryCertificatePersistence(AbstractCertificatePersistence):

    def __init__(self):
        self.counter = 0
        self.keys = {}  # type: typ.Dict[bytes, typ.Tuple[bytes, bytes]]

    def get_counter(self, key_handle: bytes) -> int:
        return self.counter

    def increment_counter(self, key_handle: bytes) -> int:
        self.counter += 1
        return self.get_counter(key_handle)

    def get_key(self, key_handle, app_param):
        app, key = self.keys[key_handle]
        if app != app_param:
            raise ValueError("Mismatched app parameter")
        return self.bytes_to_key(key)

    def store_key(self, key_handle, app_param, private_key):
        self.keys[key_handle] = (app_param, self.key_to_bytes(private_key))
