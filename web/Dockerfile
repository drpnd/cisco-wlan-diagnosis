FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
RUN apt-get update && apt-get -y install apache2 mysql-client python3
RUN apt-get -y install python3-mysql.connector software-properties-common python3-numpy python3-tz python3-tzlocal

COPY apache2.conf /etc/apache2/
COPY 000-default.conf /etc/apache2/sites-available/
RUN a2enmod rewrite
RUN a2enmod cgi
RUN a2enmod ssl
RUN a2enmod auth_digest
RUN a2enmod remoteip

COPY ../../web /var/www/html

CMD /usr/sbin/apache2ctl -D FOREGROUND
