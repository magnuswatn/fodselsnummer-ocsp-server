from datetime import datetime

import structlog
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from flask import Flask, request
from werkzeug.exceptions import HTTPException, UnsupportedMediaType
from werkzeug.wrappers.response import Response

from .config import CertificateId, OcspCa, OcspConfig
from .db import Database
from .exceptions import (
    MalFormedRequestException,
    OcspExeception,
    OversizedNonceException,
    UnknownCertificateException,
    UnknownIssuerException,
)
from .logging import LoggingMiddleware, setup_logging

app = Flask(__name__)
app.wsgi_app = LoggingMiddleware(app.wsgi_app)
logger = structlog.get_logger()


NIN_POLICY_OID = x509.ObjectIdentifier("2.16.578.1.16.3.2")


@app.route("/", methods=["POST"])
def ocsp_lookup():
    log = logger.bind()

    if request.content_type != "application/ocsp-request":
        raise UnsupportedMediaType(f"Unsupported content-type: {request.content_type}")

    raw_data = request.get_data()
    log.debug("Received request", raw_data=raw_data)

    try:
        ocsp_request = ocsp.load_der_ocsp_request(raw_data)
    except ValueError as error:
        raise MalFormedRequestException(error) from error

    ocsp_ca: OcspCa = app.config.get("ocsp_ca")
    database: Database = app.config.get("database")

    _validate_ocsp_request(ocsp_ca, ocsp_request)

    log = log.bind(
        serial=ocsp_request.serial_number, algorithm=ocsp_request.hash_algorithm.name
    )

    issued_cert = database.get_certificate(ocsp_request.serial_number)
    if issued_cert is None:
        raise UnknownCertificateException(
            f"Unknown serial number: {ocsp_request.serial_number}"
        )

    if issued_cert.revocation_time is not None:
        cert_status = ocsp.OCSPCertStatus.REVOKED
    else:
        cert_status = ocsp.OCSPCertStatus.GOOD

    log = log.bind(cert_status=cert_status.name)

    resp_builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=issued_cert.cert,
            issuer=ocsp_ca.issuer,
            algorithm=ocsp_request.hash_algorithm,
            cert_status=cert_status,
            this_update=datetime.utcnow(),
            next_update=None,
            revocation_time=issued_cert.revocation_time,
            revocation_reason=issued_cert.revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, ocsp_ca.sign_cert)
        .certificates([ocsp_ca.sign_cert])
    )

    if (nonce := _get_nonce_from_request(ocsp_request)) is not None:
        log.debug("Request has nonce", nonce=nonce)
        resp_builder = resp_builder.add_extension(x509.OCSPNonce(nonce), critical=False)

    if _is_nin_request(ocsp_request):
        log.debug("Request has NIN extension")
        log = log.bind(nin=issued_cert.nin, mapping_id=issued_cert.mapping_id)

        if len(issued_cert.nin) != 11:
            # Needed because of the ghetto asn1 encoding below.
            raise OcspExeception(f"Invalid NIN in database: {issued_cert.nin}")

        # Printable string (tag=19) with length=11
        extension_value = f"\x13\x0b{issued_cert.nin}".encode()

        nin_ext = x509.UnrecognizedExtension(NIN_POLICY_OID, extension_value)
        resp_builder = resp_builder.add_extension(nin_ext, critical=False)

    ocsp_response = resp_builder.sign(ocsp_ca.sign_key, SHA256())
    response_bytes = ocsp_response.public_bytes(Encoding.DER)

    log.debug("Returning response", response_bytes=response_bytes)
    log.info("Finished processing request")

    return Response(
        response=response_bytes,
        status=200,
        headers={"Content-Type": "application/ocsp-response"},
    )


def _is_nin_request(ocsp_req: ocsp.OCSPRequest):
    for extension in ocsp_req.extensions:
        if extension.oid == NIN_POLICY_OID:
            return True
    return False


def _get_nonce_from_request(ocsp_req: ocsp.OCSPRequest):
    for extension in ocsp_req.extensions:
        if extension.oid == x509.OCSPNonce.oid:
            # Because Andrew Ayer says so:
            # https://www.mail-archive.com/dev-security-policy@lists.mozilla.org/msg02999.html
            if (nonce_length := len(extension.value.nonce)) > 32:
                raise OversizedNonceException(
                    f"Nonce in request too large ({nonce_length})"
                )
            return extension.value.nonce
    return None


def _validate_ocsp_request(ocsp_ca: OcspCa, ocsp_req: ocsp.OCSPRequest):
    try:
        # to catch algorithms cryptography doesn't support
        ocsp_req.hash_algorithm.name
    except Exception as error:
        raise MalFormedRequestException(error) from error

    cert_id = ocsp_ca.ids.get(ocsp_req.hash_algorithm.name)
    req_cert_id = CertificateId.from_ocsp_request(ocsp_req)
    if cert_id != req_cert_id:
        raise UnknownIssuerException(f"Unknown issuer cert id: {req_cert_id}")


@app.before_first_request
def init_app():
    config = OcspConfig.create()
    setup_logging(config.debug_logging)
    database = Database(config.db_url)
    ocsp_ca = OcspCa.create(config)

    app.config.update(database=database, ocsp_ca=ocsp_ca)


@app.errorhandler(OcspExeception)
def handle_ocsp_exceptions(error):
    logger.exception(
        error, ocsp_status=error.ocsp_status.name, http_code=error.http_code
    )
    ocsp_response = ocsp.OCSPResponseBuilder().build_unsuccessful(error.ocsp_status)

    return Response(
        response=ocsp_response.public_bytes(Encoding.DER),
        status=error.http_code,
        headers={"Content-Type": "application/ocsp-response"},
    )


@app.errorhandler(HTTPException)
def handle_http_exceptions(error):
    logger.exception(error, http_code=error.code)
    return Response(
        response=None,
        status=error.code,
    )


@app.errorhandler(Exception)
def handle_exceptions(error: Exception):
    logger.exception(error)
    return Response(
        response=None,
        status=500,
    )
