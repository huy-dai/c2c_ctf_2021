#!/bin/bash

for i in $(seq 1 10);
do
    stegseek --crack -sf ./happy/id0$i.jpg -wl ./password.txt -xf out.txt -f 
    cat out.txt >> flag.txt
done

for i in $(seq 10 50);
do
    stegseek --crack -sf ./happy/id$i.jpg -wl ./password.txt -xf out.txt -f
    cat out.txt >> flag.txt
done