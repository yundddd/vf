FROM ubuntu:latest

RUN apt update

RUN apt install npm -y && npm install -g @bazel/bazelisk
RUN apt install git -y && git clone https://github.com/yundddd/vt.git
