#!/bin/bash
set -e

source infector/infector_test_util.sh

echo "Infecting EXEC victim with pt_note"
test_infection infector/victim_no_pie pt_note
