#!/bin/bash
set -e

cp infector/cavy infector/tmp
chmod 777 infector/tmp
infector/infector infector/tmp infector/so_parasite.bin
infector/tmp
