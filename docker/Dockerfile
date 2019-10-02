FROM ubuntu
MAINTAINER pbrah
RUN apt-get update && apt-get -y install iproute2 python python-pymongo
COPY eap_proxy /usr/sbin/
COPY fixit.py /usr/sbin/
RUN chmod +x /usr/sbin/eap_proxy
RUN chmod +x /usr/sbin/fixit.py
ENTRYPOINT ["/usr/sbin/eap_proxy"]
CMD []
