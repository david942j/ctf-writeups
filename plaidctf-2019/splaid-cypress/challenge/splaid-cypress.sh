#!/bin/bash

export LD_LIBRARY_PATH=".:$LD_LIBRARY_PATH"

set -ex

curl -s -o danny.jpg \
	'https://www.csd.cs.cmu.edu/sites/default/files/styles/directory_photos/public/danny-polaroid.jpg'

zip secrets.zip flag-cypress.txt danny.jpg
set +x
./splaid-cypress -e secrets.zip -o secrets.zip.enc -p "$(cat key-cypress.txt)"
set -x

rm -f splaid-cypress.zip
zip splaid-cypress.zip secrets.zip.enc splaid-cypress.sh libsplaid.so.1 splaid-cypress
rm -f secrets.zip secrets.zip.enc danny.jpg
