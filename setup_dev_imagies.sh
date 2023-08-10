#/bin/bash

# Run this script once. If the dockerfile is modified, please remove
# all created images containers first before running it again.

# biuld for both arm and x86 
docker buildx build --load --platform linux/amd64 -t ubuntu-amd64-img .
docker buildx build --load --platform linux/arm64 -t ubuntu-arm64-img .

