#/bin/bash

USERNAME=vscode
USERHOME=/home/$USERNAME

# start the container in interactive, detached mode and mount a volume for repo data.
# The container will be removed when exited and all persistent data should be in the
# repo directory and shared with the host.
docker run -h x86 -tid --rm  -v "$(pwd)":$USERHOME/vt --name ubuntu-x86 ubuntu-x86-img
docker run -h aarch64 -tid --rm  -v "$(pwd)":$USERHOME/vt --name ubuntu-aarch64 ubuntu-aarch64-img

