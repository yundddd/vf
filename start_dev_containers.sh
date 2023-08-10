#/bin/bash

# start the container in interactive, detached mode and mount a volume for repo data.
# The container will be removed when exited.
docker run -tid --rm  -v "$(pwd)":/vt --name ubuntu-amd64 ubuntu-amd64-img
docker run -tid --rm  -v "$(pwd)":/vt --name ubuntu-arm64 ubuntu-arm64-img

