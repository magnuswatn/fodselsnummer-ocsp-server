from datetime import datetime
from typing import Optional

import attr
from cryptography import x509
from cryptography.x509 import ReasonFlags
from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    LargeBinary,
    MetaData,
    String,
    Table,
    create_engine,
)
from sqlalchemy.sql import select


@attr.frozen
class IssuedCertificate:
    cert: x509.Certificate
    revocation_time: Optional[datetime]
    revocation_reason: Optional[ReasonFlags]
    mapping_id: str
    nin: str

    @classmethod
    def from_row(cls, row):
        if not row:
            return None
        [(_, raw_cert, revocation_time, revocation_reason, _, mapping_id, nin)] = row
        cert = x509.load_der_x509_certificate(raw_cert)
        return cls(cert, revocation_time, revocation_reason, mapping_id, nin)


class Database:
    def __init__(self, db_uri):
        self._metadata = MetaData()
        self._certificates = Table(
            "certificates",
            self._metadata,
            Column("serial", String, primary_key=True, nullable=False),
            Column("cert_bytes", LargeBinary),
            Column("revocation_time", DateTime),
            Column("revocation_reason", Enum(ReasonFlags)),
            Column("nin_id", String, ForeignKey("nins.id")),
        )
        self._nins = Table(
            "nins",
            self._metadata,
            Column("id", String, primary_key=True, nullable=False),
            Column("nin", String),
        )
        self._engine = create_engine(db_uri)

    def get_certificate(self, serial_number: int) -> Optional[IssuedCertificate]:
        row = self._engine.execute(
            select([self._certificates, self._nins])
            .where(self._certificates.c.serial == str(serial_number))
            .where(self._certificates.c.nin_id == self._nins.c.id)
        ).fetchall()
        return IssuedCertificate.from_row(row)
