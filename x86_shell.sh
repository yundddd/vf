#/bin/bash

REPO=/home/vscode/vt

docker exec -it -u vscode -w $REPO ubuntu_x86 zsh
