#/bin/bash

USERNAME=$(whoami)
REPO=/home/$USERNAME/vt

docker exec -it -u $USERNAME -w $REPO ubuntu_aarch64 zsh
