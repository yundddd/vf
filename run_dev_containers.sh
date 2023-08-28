#/bin/bash

X86_CONTAINER=ubuntu_x86
AARCH64_CONTAINER=ubuntu_aarch64

echo "removing old containers if they exist..."
docker ps -aq --filter "name=$X86_CONTAINER" | xargs -r docker rm -f
docker ps -aq --filter "name=$AARCH64_CONTAINER" | xargs -r docker rm -f

USERNAME=vscode
USERHOME=/home/$USERNAME

# start the container in interactive, detached mode and mount a volume for repo data.
# The container will be removed when exited and all persistent data should be in the
# repo directory and shared with the host.
docker run -h x86 -tid --rm \
       --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
       -v "$(pwd)":$USERHOME/vt \
       -v /var/run/docker.sock:/var/run/docker.sock \
       --name $X86_CONTAINER ubuntu-x86-img
docker run -h aarch64 -tid --rm \
       --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
       -v "$(pwd)":$USERHOME/vt \
       -v /var/run/docker.sock:/var/run/docker.sock \
       --name $AARCH64_CONTAINER ubuntu-aarch64-img

docker container prune -f
docker image prune -f -a
