import base64
import logging
import sys
import uuid

import structlog


class LoggingMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request_id = str(uuid.uuid4())
        structlog.threadlocal.clear_threadlocal()
        structlog.threadlocal.bind_threadlocal(
            request_id=request_id,
        )

        def new_start_response(status, response_headers, exc_info=None):
            response_headers.append(("X-EVENT-ID", request_id))
            return start_response(status, response_headers, exc_info)

        return self.app(environ, new_start_response)


def encode_bytes(_, __, event_dict):
    # Encodes field with byte values with base64
    # so that nonces and raw requests become readable.
    replacements = {}
    for x, y in event_dict.items():
        if isinstance(y, bytes):
            replacements[x] = base64.b64encode(y).decode()
    event_dict.update(replacements)
    return event_dict


def setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.threadlocal.merge_threadlocal,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            encode_bytes,
            structlog.processors.ExceptionPrettyPrinter(),
            structlog.processors.KeyValueRenderer(
                key_order=["timestamp", "logger", "level", "event", "request_id"]
            ),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
