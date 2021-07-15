from cryptography.x509.ocsp import OCSPResponseStatus


class OcspExeception(Exception):
    ocsp_status = OCSPResponseStatus.INTERNAL_ERROR
    http_code = 500


class UnknownIssuerException(OcspExeception):
    ocsp_status = OCSPResponseStatus.UNAUTHORIZED
    http_code = 400


class UnknownCertificateException(OcspExeception):
    ocsp_status = OCSPResponseStatus.UNAUTHORIZED
    http_code = 400


class MalFormedRequestException(OcspExeception):
    ocsp_status = OCSPResponseStatus.MALFORMED_REQUEST
    http_code = 400


class OversizedNonceException(OcspExeception):
    ocsp_status = OCSPResponseStatus.MALFORMED_REQUEST
    http_code = 400
