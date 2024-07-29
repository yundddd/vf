#!/bin/bash

# This script can build development containers for both x86 and arm. Usage:

# // Build arm container only
# ./build_dev_images.sh arm

# // Build x86 container only
# ./build_dev_images.sh x86

# // Build both
# ./build_dev_images.sh

build_x86() {
	docker buildx build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" --build-arg USERNAME="$(whoami)" --load --platform linux/amd64 -t ubuntu-x86-img .
}

build_arm() {
	docker buildx build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" --build-arg USERNAME="$(whoami)" --load --platform linux/arm64 -t ubuntu-aarch64-img .
}

if [ $# -gt 1 ]; then
	echo "Error: Too many arguments provided"
	exit 1
fi

if [ -z "$1" ]; then
	echo "Building docker images for both x86 and arm"
	build_arm
	build_x86
	exit 0
fi

# build dev images for both arm and x86.
if [ "$1" == "arm" ]; then
	build_arm
elif [ "$1" == "x86" ]; then
	build_x86
else
	echo "Unknown architecture " $1
fi
