FROM openquantumsafe/python:7e08920

COPY sacti sacti
COPY pyproject.toml .
RUN pip3 install . --trusted-host pypi.python.org
