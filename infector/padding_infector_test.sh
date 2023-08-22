#!/bin/bash
set -e

source infector/infector_test_util.sh

echo "Infecting DYN victim with text_padding"
test_infection infector/victim_pie text_padding

echo "Infecting EXEC victim with text_padding"
test_infection infector/victim_no_pie text_padding