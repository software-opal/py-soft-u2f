import typing as typ
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


PrivateKey = typ.Union[
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    rsa.RSAPrivateKey
]
PrivateKeyWithSerialization = typ.Union[
    dsa.DSAPrivateKeyWithSerialization,
    ec.EllipticCurvePrivateKeyWithSerialization,
    rsa.RSAPrivateKeyWithSerialization
]

PublicKey = typ.Union[
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    rsa.RSAPublicKey,
]
PublicKeyWithSerialization = typ.Union[
    dsa.DSAPublicKeyWithSerialization,
    ec.EllipticCurvePublicKeyWithSerialization,
    rsa.RSAPublicKeyWithSerialization,
]
