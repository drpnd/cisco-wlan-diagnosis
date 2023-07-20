FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
RUN apt-get update && apt-get -y install python3 python3-pip
RUN apt-get -y install mysql-client python3
RUN apt-get -y install python3-mysql.connector python3-requests python3-tz
RUN pip install cisco-gnmi

COPY mydb.py /usr/local/
COPY run.py /usr/local/
COPY config.py /usr/local/
COPY client.crt /usr/local/
COPY client.key /usr/local/
COPY rootCA.pem /usr/local/

WORKDIR /usr/local/

ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

CMD python3 run.py --host ${TARGET_HOST:=localhost}
