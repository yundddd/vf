#!/bin/bash
# this is a script that runs a series of commands to build and infect victim with different
# infection methods. This script is not sandboxed and is meant to provide convenience during
# infection algorithm development. Run with care.

# please build the //infector package before running this script.
# run with infector/infect_victim.sh [method] [victim]
# for example: bazel build //infector/... --config=gcc_x86_64 && infector/infect_victim.sh text_padding bazel-bin/infector/victim

set -e
set -o pipefail

rm -f /tmp/victim
# extract virus's text segment
chmod 700 bazel-bin/infector/test_parasite \
      && objcopy --dump-section .text=/tmp/parasite_code bazel-bin/infector/test_parasite

# copy victim to tmp to be infected
cp $2 /tmp/victim \
      && chmod 700 /tmp/victim
echo "infect111111"
bazel-bin/infector/infector /tmp/victim /tmp/parasite_code $1
echo "infected"
# run the infected binary. Since most binaries terminate with --help, this is sufficient to
# test that infection is working. In case any binaries is stuck, kill it after 1 sec.
timeout -s KILL 1 /tmp/victim --help
