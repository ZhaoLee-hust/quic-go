#!/usr/bin/env bash

# del first
tc qdisc del dev s1-eth1 root
# tc qdisc add dev s1-eth1 root handle 1: netem limit $1 delay $2ms loss $3% rate $4mbps
tc qdisc add dev s1-eth1 root handle 1: netem limit $1 delay $2ms reorder 3% loss $3% rate $4mbps

# echo "tc qdisc show"
# tc qdisc show

# tc qdisc add dev s1-eth1 root handle 1: netem limit 5000 delay 1ms loss 1%

# tc qdisc del dev s1-eth2 root
# tc qdisc add dev s1-eth2 root handle 1: netem limit $1 delay $2ms loss $3%
# tc qdisc add dev s1-eth2 root handle 1: netem limit 5000 delay 1ms loss 1%

# tc qdisc add dev s1-eth1 root handle 1: htb default 21  
# tc class add dev s1-eth1 partent 1: classid 1:1 htb rate $1mbit ceil $2mbit  

# tc qdisc add dev s1-eth2 root handle 1: htb default 21  
# tc class add dev s1-eth2 partent 1: classid 1:1 htb rate $1mbit ceil $2mbit 

# # set queue delay and loss rate
# tc qdisc add dev s1-eth1 root netem limit  1000  delay $3ms loss $4%
# tc qdisc add dev s1-eth2 root netem limit  1000 delay $3ms loss $4%

#