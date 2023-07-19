FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update
RUN apt-get -y install mysql-client python3
RUN apt-get -y install python3-mysql.connector python3-requests python3-tz
RUN apt-get -y install snmptrapd

COPY snmptrapd.conf /etc/
COPY mydb.py /usr/local/
COPY trap_handler.py /usr/local/
COPY config.py /usr/local/

WORKDIR /usr/local/

CMD ["sh","-c","snmptrapd -Lsd -Lf /var/log/snmptrapd.log -f -On -c /etc/snmptrapd.conf"]
