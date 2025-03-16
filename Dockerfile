FROM ubuntu:24.04

# Evita domande interattive durante l’installazione
ENV DEBIAN_FRONTEND=noninteractive \
    DIR_SAMBA_CONF=/etc/samba/conf.d \
    DIR_SCRIPTS=/scripts \
    DIR_GPO=/gpo 

# Aggiorna e installa Samba AD DC, Winbind e Kerberos
RUN apt-get update && \
    apt-get install -y ntp pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils krb5-user krb5-kdc winbind libpam-winbind libnss-winbind libpam-krb5 supervisor dnsutils && \
    apt-get clean autoclean && \
    apt-get autoremove --yes && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/ && \
    rm -fr /tmp/* /var/tmp/*

# Copia i file di configurazione
COPY ./scripts /scripts
COPY ./etc /etc
COPY ./gpo /gpo

RUN chmod -R +x $DIR_SCRIPTS

# Esponi le porte necessarie per AD DC
EXPOSE 42 53 53/udp 88 88/udp 135 137-138/udp 139 389 389/udp 445 464 464/udp 636 3268-3269 49152-65535

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1

# Imposta lo script come comando di default
ENTRYPOINT ["bash", "/scripts/init.sh"]

