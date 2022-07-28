FROM python:3.10-alpine3.15


COPY ./*.py /opt/certs/
COPY ./requirements.txt /requirements.txt

RUN pip install --no-cache-dir -r /requirements.txt && chmod +x /opt/certs/corp_cert.py && mkdir /var/lib/zabbix

VOLUME [ "/var/lib/zabbix" ]
WORKDIR /opt/certs

ENTRYPOINT [ "/opt/certs/corp_cert.py" ]
# ENTRYPOINT [ "/bin/sh" ]