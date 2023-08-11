FROM ubuntu:latest

# install all dependencies
RUN apt-get update && apt-get install zsh sudo git wget curl binutils npm nasm build-essential -y


RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# switch default shell
RUN chsh -s $(which zsh)
COPY .zshrc /home/$USERNAME/

# setup non-root user that also works with vscode container dev plugin.
# we don't want viruses to have root by default.
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# set default user
USER $USERNAME

# Since containers will run locally with the repo in a shared drive
# it is safe to have users commit inside of containers. Since no key is
# setup, containers don't have permission to push.
RUN git config --global --add safe.directory "*" \
    && git config --global user.name "vt container dev" \
    && git config --global user.email "dummy@dummy.com"

# We want the container to be the main dev place.
CMD ["/bin/zsh"]
