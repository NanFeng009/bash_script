#!/bin/bash

total=100
sum=0

start=`date +%s`
echo "Start to $total times long term pairing"
for ((i=0;i<${total};i++))
do
	echo "Do the $i th times long term pairing"
	#LD_LIBRARY_PATH=. ./seautotestPSW -auto pse 1 2>&1 | grep "Success:\ 1"
	if LD_LIBRARY_PATH=. ./seautotestPSW -auto pse 1 2>&1 | tail -n 1 | grep "Success:\ 1"; then
		((sum++))
		sleep 2
		if ! rm /var/opt/aesmd/data/LTPairing.blob; then
			echo "can NOT delete LTPairing.blob."
			break
		fi
	else
		echo "long term failure and break"
		break
	fi

done


end=`date +%s`
echo "Successfully do long term compairing $sum/$total in $(($((end-start))/60)) mins"

