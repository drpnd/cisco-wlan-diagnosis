FROM ubuntu:22.04

RUN apt-get update && apt-get -y install mysql-client syslog-ng

RUN mkdir -p /var/log/net
COPY syslog-ng.conf /etc/

CMD ["syslog-ng","-f","/etc/syslog-ng.conf","-F","--no-caps"]
