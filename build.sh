#!/bin/bash
# Simple build script for Debian source package.
# Builds a binary package, moves it to dist/, and cleans
pkgname=eap-proxy
mkdir -p dist
if dpkg-buildpackage -us -uc && mv ../$pkgname_*_all.deb dist/; then
	read -p "Build succeeded. Clean? [Y|n]: " ans
	ans=$(echo "$ans" | tr [:lower:] [:upper:])
	if ([ -z "$ans" ] || [ "$ans" = "Y" ]); then
		debian/rules clean
	fi
fi
