#!/bin/bash
set -e

source infector/infector_test_util.sh

echo "Infecting EXEC victim with reverset_text"
test_infection infector/victim_no_pie reverse_text
