[![CircleCI](https://dl.circleci.com/status-badge/img/gh/yundddd/vt/tree/master.svg?style=svg&circle-token=e2d070ac00987abbcbd0410247d9dc9b4102775d)](https://dl.circleci.com/status-badge/redirect/gh/yundddd/vt/tree/master)
![](https://img.shields.io/badge/infects-x86_64-blue)
![](https://img.shields.io/badge/infects-aarch64-yellow)


Writing a virus is hard due to the following reasons:

# The parasite must be self-contained
This means that it relies on no external linking, is position independent (PIC), and is able to dynamically adjust memory addresses based on the host; the addresses will change between each infection due to address space layout randomization (ASLR). This implies we cannot refer to any thing that lives outside of .text section, or anything that doesn't use relative addressing. This poses difficulties because some system calls require initialized strings. To work around this, we provide a generic wrapper for you to define a string literal in text section with relative addressing code in macro.hh. One may also merge .rodata into .text. It may work on x86 PC relative instructions, but on aarch64, it may not. If your virus is not constrained by code size, feel free to use string.hh and simply append charaters to it. One might think putting a char[] on stack and initialize it there might work, however the compiler might try to be smart and put it in .rodata for you. Do an objdump to confirm before you go with this route.

# No global variables

We should not refer to anything in .data sections that is global, such as environ and errno. Our build system macro is setup in a way that prevents linker from finding them and will error out at compile time. We should not use global C++ objects, since we don't have glibc's .init and friends. If you still want to, the constructors and destructors will not be called. This also applies to function static or anything that has global life time.

# No glibc

We rolled our own startup code as well as common utilities. Note that a subset of them are not suitable for viruses as they might take up too much space (ex. sprintf). Use them for developing viruses only. The startup code maybe patched to hand control back to host, while restoring important registers as if nothing has happened before host's entry. 

# Your virus needs to be patched to hand control back to host.

Our startup code follows this convention for patching: for x86-64, the last 8 nop instructions should be patched to a jump instruction; for aarch64, the last nop instruction (4bytes) should be patched to a branch instruction.

# Your virus needs to be inserted to the host binary in an appropriate place.

We provided algorithms for users to choose, each with their own trade-offs on space, efficiency, and potential virus life-time (detectability). Please see //infector for more information.

# It's hard to test viruses.

Our build system is setup in a way that allows us to select two binary modes (virus and normal). The former links our virus startup code, that enables patching and register restoration. The latter is simplier, and exposes environ, makes writing unittests/tools easier since we are not writing viruses any more. We also provide a test framework, that mimics GTEST framework, to make testing familiar to users.

# Docker

This framework is targeting both x86 and aarch64. Therefore we will need to run our code on two architectures.
The development is streamlined by docker, as switching between machines can be tedious; this section discribes
a workflow that can potentially work on all systems.

Acquire a development machine (mac, windows or linux) and install install [docker desktop](https://www.docker.com/products/docker-desktop/). Also, fork this repo and clone it to your development machine, let's say, to `/home/$USER/vt`.

```
# go to https://github.com/yundddd/vt and press on the fork button to make a copy of the repo under your name.
# on development machine, run:
cd ~
git clone git@github.com:$YOUR_GIT_USERNAME/vt.git
```

Now, build images for x86 and aarch64, which will be used to create containers that can test your virus:
```
cd vt
./build_dev_images.sh && ./run_dev_containers.sh
```
These commands will make two containers available for you, with direct access to the cloned repo. You can build and debug code inside the containers by:

```
# acquire a shell to the x86 container
./x86_shell.sh
$ vscode@x86 ~/vt master

# acquire a shell to the aarch64 container
./aarch64_shell.sh
$ vscode@xaarch64 ~/vt master
```

The containers have setup everything you need to build and debug your code. The repo is mounted at /home/vscode/vt. The default non-root user is called `vscode` to facilitate those who use vscode docker plugin. It is also in sudoer file. Note that the machine type is displaced on the prompt in case you have multiple terminals running.

Under the hood, these two containers mount our repo and all share the same code with our development host. In other words, any changes to our code will be immediately available to build and run inside our containers.

Note: The containers do not have permission to push to your repo, in fact they don't even have git user or email setup to commit any changes. Ideally you should only commit and push from your development machine.

Note: Users should not save any important data in containers as they do not perserve them. If there is any update to dockerfile, re-run these commands to refresh the containers. Users should only modify the code folder inside the containers.


# Infection Algorithm

In this repo we present various infection algorithms that can infect:

| Algorithm     | x86_64 DYN    | x86_64 EXEC       | aarch64 DYN       | aarch64 EXEC      |
| ------------- | ------------- | ----------------  | ----------------  | ----------------  |
| text_padding  |:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|
| reverse_text  | :question:    |:heavy_check_mark: | :question:        |:heavy_check_mark: |
| pt_note       |:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|

To infect a single binary, run the following command:
```
# build the infector and sample virus first
bazel build //infector/... --config=gcc_aarch64
# infect a single binary (a copy of /usr/bin/ls) using the `text_padding` algorithm. 
infector/infect_victim.sh text_padding /usr/bin/ls
```

To infect all binaries from a path, run:
```
bazel build //infector/... --config=gcc_aarch64
# infect all binaries in /usr/bin using the `text_padding` algorithm. 
infector/infect_victims.sh text_padding /usr/bin
```

The scripts will make a copy of the victim binary and infect it with a sample virus. For more details please read the source.

The Text Padding infection was devised by Silvio Cesare in 1998. It takes advantage of the fact that ELF binaries are mapped into memory by pages, as we can only set access/execution control on page boundary. The TEXT segment has the execution bit set, while the next segment does not. This means, if the TEXT segment doesn't use up all the space in a page, there will be holes in our ELF file. This algorithm injects a virus into this space (provided there is enough space) and takes over the entry point to execute it first, before handing control back to the original entry point.

