FROM openquantumsafe/python:7e08920
USER root
RUN apk add git
COPY sacti sacti
COPY requirements.txt .
RUN pip3 install -r requirements.txt
