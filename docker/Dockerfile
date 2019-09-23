FROM ubuntu
MAINTAINER pbrah
RUN apt-get update && apt-get -y install iproute2 python
COPY eap-proxy_0.0.2_all.deb /tmp/
RUN dpkg -i /tmp/eap-proxy_0.0.2_all.deb
ENTRYPOINT ["/usr/sbin/eap_proxy"]
CMD []
