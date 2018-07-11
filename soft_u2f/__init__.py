
# CERT = base64. b64decode(b"""
# MIIBhzCCAS6gAwIBAgIJAJm+6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwW
# WXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYx
# NDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcq
# hkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ+w3gnnXEPIBl1J3pol6IviRAMc
# /hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF/XCGvHYEto1AwTjAdBgNVHQ4E
# FgQUDai/k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai/k1dOImjupkub
# YxhOkoX3sZ4wDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnY
# VWhuyCbZ+OKNtSpovBB7A5OHAH52dK9/AiEA+mT4tz5eJV8W2OwVxcq6ZIjrwqXc
# jXSy2G0k27yAUDk=
# """)
# print(CERT)
# cert = x509.load_der_x509_certificate(
#     data=CERT,
#     backend=default_backend()
# )
# print(CERT == cert.public_bytes(serialization.Encoding.DER))
#
# print({name: getattr(cert, name) for name in dir(cert) if name[0] != '_'})
# print(*cert.extensions, sep="\n")
#
#
# builder = x509.CertificateBuilder()
# builder = builder.subject_name(x509.Name([
#     x509.NameAttribute(NameOID.COMMON_NAME, 'Yubico U2F Soft Device'),
# ])).issuer_name(x509.Name([
#     x509.NameAttribute(NameOID.COMMON_NAME, 'Yubico U2F Soft Device'),
# ])).not_valid_before(
#     datetime.datetime(2013, 7, 17, 14, 21, 3),
# ).not_valid_after(
#     datetime.datetime(2016, 7, 16, 14, 21, 3),
# ).serial_number(
#     11078547980496858140,
# ).public_key(
#     public,
# ).add_extension(
#     x509.BasicConstraints(ca=True, path_length=None),
#     critical=True,
# )
# new_cert = builder.sign(
#     private_key=cert_priv,
#     algorithm=hashes.SHA256(),
#     backend=default_backend()
# )
#
# print(CERT == new_cert.public_bytes(serialization.Encoding.DER))
# print({name: getattr(new_cert, name)
#        for name in dir(new_cert) if name[0] != '_'})
# print(*new_cert.extensions, sep="\n")
