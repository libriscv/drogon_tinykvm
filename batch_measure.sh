#!/bin/bash
for i in {1..50}
do
	echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
	source ./measure.sh
done
