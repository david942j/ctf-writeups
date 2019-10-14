#!/bin/sh

set -x
for i in t1 t2 t3
do
  ./run_tests /home/poe/luna user_data/$i.in user_data/$i.out
done
set +x
