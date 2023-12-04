#!/bin/bash

USERNAME=$(whoami)
REPO=/home/${USERNAME}/vf

docker exec -it -u "${USERNAME}" -w "${REPO}" ubuntu_x86 zsh
