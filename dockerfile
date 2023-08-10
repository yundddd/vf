FROM ubuntu:latest

# Install all dependencies
RUN apt update && apt install git sudo binutils npm nasm build-essential -y

# Install bazel
#RUN npm install -g @bazel/bazelisk


# Add a non-root user
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME


# Set the default user.
USER $USERNAME
ENTRYPOINT ["/bin/bash"]
