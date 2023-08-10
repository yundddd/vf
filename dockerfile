FROM ubuntu:latest

# Install all dependencies
RUN apt update && apt install git sudo binutils npm nasm build-essential -y

# Install bazel
RUN npm install -g @bazel/bazelisk

# Add a non-root user
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME


# Set the default user. We do not want root to be default which gives
# viruses too much power.
USER $USERNAME

# Since containers will run locally with the repo in a shared drive
# this is safe.
RUN git config --global --add safe.directory "*"

# We want the container to be the main dev place.
ENTRYPOINT ["/bin/bash"]
