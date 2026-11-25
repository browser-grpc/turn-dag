#!/bin/sh
set -eu
echo "== build =="
test -f docs/bond-contract-fraud-proof-spec.pdf
pdfinfo docs/bond-contract-fraud-proof-spec.pdf | head -20 || file docs/bond-contract-fraud-proof-spec.pdf
ls -lh docs/ README.md LICENSE Dockerfile
echo "build: PASS"
