PREFIX  ?= /usr
GZIP    ?= /bin/gzip
CONFDIR ?= ${DESTDIR}/etc
MANDIR  ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR ?= ${DESTDIR}${PREFIX}/sbin

all: eap_proxy eap_proxy.1.gz eap_proxy.conf

install: all
	mkdir -p ${SBINDIR} ${MANDIR}/man1 ${CONFDIR}
	cp eap_proxy ${SBINDIR}
	chmod +x ${SBINDIR}/eap_proxy
	cp eap_proxy.1.gz ${MANDIR}/man1
	cp eap_proxy.conf ${CONFDIR}

eap_proxy.1.gz:
	${GZIP} < eap_proxy.1 > eap_proxy.1.gz

eap_proxy:
	cp eap_proxy.py eap_proxy

eap_proxy.conf:
	cp eap_proxy.conf-dist eap_proxy.conf

clean:
	rm -f eap_proxy eap_proxy.1.gz eap_proxy.conf
