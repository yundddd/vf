#!/bin/bash
set -e

# A simple test case to make sure we can infect
cp infector/victim infector/tmp_host
cp infector/test_parasite infector/tmp_test_parasite
chmod 700 infector/tmp_host
chmod 700 infector/tmp_test_parasite

objcopy --dump-section .text=infector/bin infector/tmp_test_parasite

infector/infector infector/tmp_host infector/bin reverse_text

infector/tmp_host
