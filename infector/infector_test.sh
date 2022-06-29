#!/bin/bash
set -e

cp infector/cavy infector/tmp
cp infector/so infector/tmp_so
chmod 700 infector/tmp
chmod 700 infector/tmp_so

objcopy --dump-section .text=infector/bin infector/tmp_so
infector/infector infector/tmp infector/bin
infector/tmp
