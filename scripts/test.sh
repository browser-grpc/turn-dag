#!/bin/sh
set -eu
echo "== test =="
test -f docs/bond-contract-fraud-proof-spec.pdf
test -s docs/bond-contract-fraud-proof-spec.pdf
file docs/bond-contract-fraud-proof-spec.pdf | grep -qi pdf
grep -q "Bond Contract" README.md
grep -q "Apache" LICENSE
echo "spec checks: PASS"
