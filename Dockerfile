FROM python:3.8.2-slim-buster

RUN set -x && python3 -m venv /opt/fodselsnummer-ocsp-server/venv

ENV PATH="/opt/fodselsnummer-ocsp-server/venv/bin:${PATH}"

RUN set -x && pip --no-cache-dir --disable-pip-version-check install --upgrade pip

COPY requirements.txt /tmp/requirements.txt

RUN set -x && pip --no-cache-dir install -r /tmp/requirements.txt

COPY ./fodselsnummer_ocsp_server /opt/fodselsnummer-ocsp-server/app/fodselsnummer_ocsp_server

WORKDIR /opt/fodselsnummer-ocsp-server/app

EXPOSE 8000

ENTRYPOINT ["python", "-m", "fodselsnummer_ocsp_server"]
