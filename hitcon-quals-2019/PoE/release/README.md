# Path of Exploitation

## PoE I - Luna

- Analyze the binary `luna` should be enough for solving this challenge.
- There's a proof-of-work challenge on remote service.

## PoE II - Cord

- No PoW, but you have to solve PoE I to get the password for this challenge.
- A file uploader is provided on remote for your convenience.
- Linux commit 4d856f72c10ecb060868ed10ff1b1453943fc6c8, tag: v5.3

## PoE III - TPU

- Solve PoE II to get the password for this challenge.
- Don't waste time on the binaries under pc-bios/, they are normal BIOS.
- You can upload a file as PoE II does, the uploaded file will be executed under *root* permission.
- Flag: `/home/poe/flag` on host.
- Run on the latest Ubuntu 18.04.
- QEMU commit 9e06029aea3b2eca1d5261352e695edc1e7d7b8b, tag: v4.1.0


* All services have a hard timeout 120 seconds.
