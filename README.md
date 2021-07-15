fodselsnummer-ocsp-server
===

This is an OCSP server that supports the Norwegian extension for NIN lookup according to "SEID Leveranse 2". It does not currently support any means of authenticating the requester (no signature check), and is really only ment for testing purposes.

The OCSP response from this server will contain the NIN extension (OID 2.16.578.1.16.3.2) with the user's NIN, if the request contained the NIN extension. Only requests with a single certificate status request is supported, so the extension in the response will be in a responseExtensions attribute, not in the singleExtensions attribute.


## Populating the database

The database has two tables; the certificates, and the mapping from the ID in the certificates to the person's current NIN. This can be populated by the create_db.py script. It needs:

* A CSV file that holds the mapping between the IDs from the subject to the current NIN. If there are certificates with NIN in the subject, those need to be in the mapping file as well. Example:

```csv
9578-1234-123456789,12345678911
9578-1234-123456788,12345678912
9578-1234-123456787,12345678913
9578-1234-438970139,12345678914
12345678915,12345678915
```

* A folder with all the end entity certificates.

* The current CRL from the CA.

* The connection string to the database.

So something like this:

```bash
PYTHONPATH=. python ./utils/create_db.py sqlite:///db.db mappings.csv MY-CA.crl all_my_certs
```

## Running

The server needs a delegated OCSP signing certificate with it's private key. It also needs a copy of the issuing certificate.

The server is configured via the following environment variables:

* `OCSP_DB_URL` <- url to the database
* `OCSP_ISSUER_CERT` <- Path to the issuer certificate, in PEM format.
* `OCSP_SIGNER_CERT` <- Path to the ocsp signer certificate, in PEM format.
* `OCSP_SIGNER_KEY` <- Path to the ocsp signing certificate key, in unencrypted PEM format.
* `OCSP_WORKERS` <- amount of workers. Will default to something kind of reasonable.
* `OCSP_BIND` <- What the server should bind to. Defaults to `0.0.0.0:8000`
* `OCSP_DEBUG_LOGGING` <- debug logging or not.

The server can be run in a Docker container. Example:

```bash
docker build -t fodselsnummer-ocsp-server .

docker run -v $PWD/config:/config \
  -e OCSP_DB_URL=sqlite:////config/db.db \
  -e OCSP_ISSUER_CERT=/config/issuer.pem \
  -e OCSP_SIGNER_CERT=/config/signer.pem \
  -e OCSP_SIGNER_KEY=/config/signer_key.pem \
  -p 8000:8000 \
  --name fodselsnummer-ocsp-server \
  fodselsnummer-ocsp-server
```
