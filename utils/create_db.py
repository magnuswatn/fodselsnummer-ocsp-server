#!/bin/env python3
"""
Script for å populere databasen med sertifikater.

Trenger en mappingfil med kobling mellom ID og fødselsnummer,
en mappe med alle sertifikatene som skal legges inn, og CRL-en
fra CA-en, for å vite hvilke sertifikater som er revokert.
"""
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from fodselsnummer_ocsp_server.db import Database


def create_database(db_url):
    db = Database(db_url)
    db._metadata.create_all(db._engine)
    return db


def insert_mappings(mapping_file: Path, db: Database):
    print("Inserting mappings")
    for line in mapping_file.read_text().splitlines():
        id, nin = line.split(",")
        print(f"Inserting mapping for f{id}=f{nin}")
        db._engine.execute(
            db._nins.insert().values(
                id=id,
                nin=nin,
            )
        )


def insert_certs(certs_folder: Path, crl_file: Path, db: Database):
    print("Inserting certificates")
    crl = x509.load_der_x509_crl(crl_file.read_bytes())

    for path in certs_folder.iterdir():
        cert = x509.load_pem_x509_certificate(path.read_bytes())

        serial_number_attrs = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if not serial_number_attrs:
            print(f"Cert withouth serial. Skipping")
            continue

        serial_number_attr = serial_number_attrs[0].value

        if serial_number_attr[:6] not in ["UN:NO-", "PNONO-"]:
            print(f"Unexpected serial number format! {serial_number_attr}")
            continue

        mapping_id = serial_number_attr[6:]

        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        revocation_time = (
            revoked_cert.revocation_date if revoked_cert is not None else None
        )

        print(
            f"Inserting cert with serial={cert.serial_number} "
            f"mapping={mapping_id} revocation_time={revocation_time}"
        )

        db._engine.execute(
            db._certificates.insert().values(
                serial=cert.serial_number,
                cert_bytes=cert.public_bytes(Encoding.DER),
                revocation_time=revocation_time,
                revocation_reason=None,
                nin_id=mapping_id,
            )
        )


def validate_params():
    try:
        db_url = sys.argv[1]
        mapping_file = Path(sys.argv[2])
        crl_file = Path(sys.argv[3])
        certs_folder = Path(sys.argv[4])
    except IndexError:
        print("Arguments: db_url mapping_file crl_file certs_folder")
        sys.exit(1)
    if not all([mapping_file.is_file(), crl_file.is_file(), certs_folder.is_dir()]):
        print("Specified files/folders not found")
        sys.exit(1)
    return db_url, mapping_file, crl_file, certs_folder


def main():
    db_url, mapping_file, crl_file, certs_folder = validate_params()
    db = create_database(db_url)
    insert_mappings(mapping_file, db)
    insert_certs(certs_folder, crl_file, db)
    print("Done")


if __name__ == "__main__":
    main()
