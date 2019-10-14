#!/bin/sh

timeout -s KILL 30 /usr/bin/nsjail -Q --env HOME=/home/welcome -Mo --chroot / -D /home/welcome --stderr_to_null -- \
	/bin/sh -c '/usr/bin/vim -y && cat flag'
