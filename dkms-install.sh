#!/bin/bash

VERSION=0.10
MODULE_DIR="/usr/src/isgx-$VERSION"

mkdir -p "$MODULE_DIR/src"
cp -r * "$MODULE_DIR/src"
mv "$MODULE_DIR/src/dkms.conf" "$MODULE_DIR/"
cat Makefile | sed "s/KERNELRELEASE/PATCHLEVEL/g" > "$MODULE_DIR/src/Makefile"
dkms add -m isgx -v "$VERSION"
dkms build -m isgx -v "$VERSION" --verbose
dkms install -m isgx -v "$VERSION"
