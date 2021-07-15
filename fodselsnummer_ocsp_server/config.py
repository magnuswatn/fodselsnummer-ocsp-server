from pathlib import Path
from typing import Dict

import attr
import environ
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ocsp

from .exceptions import OcspExeception

SUPPORTED_HASH_ALGORITHMS = [SHA1(), SHA256()]


@environ.config(prefix="OCSP")
class OcspConfig:
    db_url: str = environ.var()
    issuer_cert: Path = environ.var(converter=Path)
    signer_cert: Path = environ.var(converter=Path)
    signer_key: Path = environ.var(converter=Path)
    bind: str = environ.var(default="0.0.0.0:8000")
    workers: int = environ.var(default=0, converter=int)
    debug_logging: bool = environ.bool_var(default=False)

    @classmethod
    def create(cls) -> "OcspConfig":
        return environ.to_config(cls)


@attr.frozen
class CertificateId:
    name_hash: bytes
    key_hash: bytes

    @classmethod
    def from_ocsp_request(cls, ocsp_req: ocsp.OCSPRequest):
        return cls(ocsp_req.issuer_name_hash, ocsp_req.issuer_key_hash)


@attr.frozen
class OcspCa:
    ids: Dict[str, CertificateId]
    issuer: x509.Certificate
    sign_cert: x509.Certificate
    sign_key: RSAPrivateKey

    @classmethod
    def create(cls, config: OcspConfig):
        issuer = x509.load_pem_x509_certificate(config.issuer_cert.read_bytes())
        sign_cert = x509.load_pem_x509_certificate(config.signer_cert.read_bytes())
        sign_key = serialization.load_pem_private_key(
            config.signer_key.read_bytes(),
            password=None,
        )
        if not isinstance(sign_key, RSAPrivateKey):
            raise OcspExeception("Only RSA key is supported")

        ids = {}
        for hash_algorithm in SUPPORTED_HASH_ALGORITHMS:
            name_hash = hashes.Hash(hash_algorithm)
            name_hash.update(issuer.subject.public_bytes())
            issuer_name_hash = name_hash.finalize()

            key_hash = hashes.Hash(hash_algorithm)
            key_hash.update(
                issuer.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
            )
            issuer_key_hash = key_hash.finalize()

            ids[hash_algorithm.name] = CertificateId(issuer_name_hash, issuer_key_hash)

        return cls(ids, issuer, sign_cert, sign_key)
