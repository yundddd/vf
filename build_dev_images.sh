#/bin/bash

# build dev images for both arm and x86.
docker buildx build --load --platform linux/amd64 -t ubuntu-x86-img .
docker buildx build --load --platform linux/arm64 -t ubuntu-aarch64-img .

docker image prune -f
