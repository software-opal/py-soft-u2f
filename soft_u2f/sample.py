
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

YUBICO_SAMPLE_PUBLIC_CERT = x509.load_der_x509_certificate(
    data=base64.b64decode(b"""
MIIBhzCCAS6gAwIBAgIJAJm+6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwW
WXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYx
NDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ+w3gnnXEPIBl1J3pol6IviRAMc
/hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF/XCGvHYEto1AwTjAdBgNVHQ4E
FgQUDai/k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai/k1dOImjupkub
YxhOkoX3sZ4wDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnY
VWhuyCbZ+OKNtSpovBB7A5OHAH52dK9/AiEA+mT4tz5eJV8W2OwVxcq6ZIjrwqXc
jXSy2G0k27yAUDk=
    """),
    backend=default_backend()
)

YUBICO_SAMPLE_PRIVATE_KEY = load_pem_private_key(
    b"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMyk3gKcDg5lsYdl48fZoIFORhAc9cQxmn2Whv/+ya+2oAoGCCqGSM49
AwEHoUQDQgAEO+GX3XN+mD2fsN4J51xDyAZdSd6aJeiL4kQDHP4QiGRWww8DLOG0
lnhXcKoxn4w5SAgK3ZozFpwxf1whrx2BLQ==
-----END EC PRIVATE KEY-----
    """,
    password=None,
    backend=default_backend(),
)
