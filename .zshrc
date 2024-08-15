# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:/usr/local/bin:$PATH

# Path to your oh-my-zsh installation.
export ZSH="$HOME/.oh-my-zsh"

# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/ohmyzsh/ohmyzsh/wiki/Themes
ZSH_THEME="alanpeabody"

export LC_ALL=C.UTF-8

plugins=(git)

source $ZSH/oh-my-zsh.sh
alias bb="bazel build"
alias btest="bazel test"

export GDBHISTFILE="$HOME/.gdbhistory"
touch $GDBHISTFILE

# make sure docker sock can be accessed to support docker
# outside of docker tests.
sudo chmod 666 /var/run/docker.sock
