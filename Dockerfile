FROM openquantumsafe/python:175a5449aa5a

COPY sacti sacti
COPY pyproject.toml .
RUN pip install .
