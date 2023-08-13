#!/bin/bash
set -e

# A simple test case to make sure we can infect
cp infector/victim infector/tmp_victim
cp infector/test_parasite infector/tmp_test_parasite
chmod 700 infector/tmp_victim
chmod 700 infector/tmp_test_parasite

objcopy --dump-section .text=infector/bin infector/tmp_test_parasite

file_attr_pre_injection=$(ls -la infector/tmp_victim)

infector/infector infector/tmp_victim infector/bin text_padding

file_attr_post_injection=$(ls -la infector/tmp_victim)

if [ "$file_attr_post_injection" != "$file_attr_pre_injection" ]; then
    echo "Host file attributes must be the same before and after injection"
    exit -1
fi

infector/tmp_victim
