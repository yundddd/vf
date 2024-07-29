#!/bin/bash

X86_CONTAINER=ubuntu_x86
AARCH64_CONTAINER=ubuntu_aarch64

echo "removing old containers if they exist..."
docker ps -aq --filter "name=${X86_CONTAINER}" | xargs -r docker rm -f
docker ps -aq --filter "name=${AARCH64_CONTAINER}" | xargs -r docker rm -f

USERNAME=$(whoami)
USERHOME=/home/$USERNAME

run_x86() {
	docker run -h x86 -tid \
		--cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
		-v "$(pwd)":"${USERHOME}"/vf:z \
		-v /var/run/docker.sock:/var/run/docker.sock \
		--name "${X86_CONTAINER}" ubuntu-x86-img
}

run_arm() {
	docker run -h aarch64 -tid \
		--cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
		-v "$(pwd)":"${USERHOME}"/vf:z \
		-v /var/run/docker.sock:/var/run/docker.sock \
		--name "${AARCH64_CONTAINER}" ubuntu-aarch64-img
}

if [ $# -gt 1 ]; then
	echo "Error: Too many arguments provided"
	exit 1
fi

if [ -z "$1" ]; then
	echo "Building docker images for both x86 and arm"
	run_arm
	run_x86
	exit 0
fi

# build dev images for both arm and x86.
if [ "$1" == "arm" ]; then
	run_arm
elif [ "$1" == "x86" ]; then
	run_x86
else
	echo "Unknown architecture " $1
fi

docker container prune -f --filter "label!=$AARCH64_CONTAINER" --filter "label!=$X86_CONTAINER"
docker image prune -f -a --filter "label!=$AARCH64_CONTAINER-img" --filter "label!=$X86_CONTAINER-img"
