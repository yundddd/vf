#!/bin/bash

# build dev images for both arm and x86.
docker buildx build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" --build-arg USERNAME="$(whoami)" --load --platform linux/amd64 -t ubuntu-x86-img .
docker buildx build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" --build-arg USERNAME="$(whoami)" --load --platform linux/arm64 -t ubuntu-aarch64-img .
