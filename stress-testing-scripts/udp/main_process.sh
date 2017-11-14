#!/bin/bash

# Populate the list holding the remaining flows per rate group
for i in `seq 1 250`;
do
        rates[$i]=20
done

# Variable initialization
start=1
end=250
flowid=10000

while [ $start -le $end ]
do
        # Pick a random group
        # Check if it is empty or not and proceed
        i=`shuf -i $start-$end -n 1`
        if [ ${rates[$i]} -ne 0 ]
        then
                ((rates[$i]--))
                # Use the destination port as a rate identifier
                dport=$((2000+i))
                # Calculate rate/Interval of flow
                rate=$((i*10))
                interval=$((1000000/rate))
                # Unique source port every time (unique flow)
                ((flowid++))
                # Start traffic
                #echo $i

               # sudo hping3 30.30.30.21 -a 30.30.30.20 --udp --keep -s $flowid -p $dport --quiet -i u$interval &
 
                sudo ~/DPDK_TGen/MoonGen/build/MoonGen stress-testing-scripts/udp/mflows_pps_lat_ver1.lua 0 1 --rate_pps=rate --sport=$flowid --dport=$dport --queue_pair=$i --tstamp=true 
        elif [ $i -eq $start ]
        then
                temp=$start
                while [ ${rates[$temp]} -eq 0 ]
                do
                        ((start++))
                        ((temp++))
                done
        elif [ $i -eq $end ]
        then
                temp=$end
                while [ ${rates[$temp]} -eq 0 ]
                do

                        ((temp--))
                        ((end--))
                done
        fi
done

# Wait for a period of time
sleep 20
echo 'DONE!'

# Kill all remaining processes
#sudo killall hping3
