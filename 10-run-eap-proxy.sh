#!/bin/sh

if podman ps -a | grep eap_proxy &>/dev/null; then
    podman start eap_proxy-udmpro
else
    podman run --privileged --network=host --name=eap_proxy-udmpro --log-driver=k8s-file --restart always -d -ti pbrah/eap_proxy-udmpro:v1.1 --update-mongodb --ping-gateway --ignore-when-wan-up --ignore-start --ignore-logoff --set-mac eth8 eth9
fi
