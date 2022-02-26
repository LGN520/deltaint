#if [ $# -ne 2 ]
#then
#	echo Usage: bash BW_evaluate.sh scale-k epoch-length
#	exit -1
#fi

dir="../packet/tmp"
files=($(ls $dir/h*_BW.txt))
filenum=${#files[*]}

TOTAL_INTPATH_BW=0
TOTAL_DINT_BW=0
TOTAL_INTPACKET_NUM=0
for i in $(seq 0 $[$filenum - 1])
do
	lastline=$(tail -n 1 ${files[i]})
	if [ ${#lastline} -gt 0 ]
	then
		INTPATH_BW=$(echo $lastline | awk '{print $2}')
		DINT_BW=$(echo $lastline | awk '{print $4}')
		INTPACKET_NUM=$(echo $lastline | awk '{print $6}')
		TOTAL_INTPATH_BW=$[$TOTAL_INTPATH_BW + $INTPATH_BW]
		TOTAL_DINT_BW=$[$TOTAL_DINT_BW + $DINT_BW]
		TOTAL_INTPACKET_NUM=$[$TOTAL_INTPACKET_NUM + $INTPACKET_NUM]
	fi
done

# Metric 1: bandwidth usage
#TOTAL_INTPATH_BW_MBPS=$(echo "scale=3;$TOTAL_INTPATH_BW/10.0/1024.0/1024.0" | bc)
#TOTAL_DINT_BW_MBPS=$(echo "scale=3;$TOTAL_DINT_BW/10.0/1024.0/1024.0" | bc)
#ratio=$(echo "scale=3;$TOTAL_DINT_BW_MBPS/$TOTAL_INTPATH_BW_MBPS" | bc)
#echo total bandwidth usage of INT-Path is $TOTAL_INTPATH_BW_MBPS Mbps
#echo total bandwidth usage of DeltaINT is $TOTAL_DINT_BW_MBPS Mbps
#echo ratio is $ratio%

# Metric 2: average bit
INTPATH_AVERAGE_BIT=$(echo "scale=3;$TOTAL_INTPATH_BW/$TOTAL_INTPACKET_NUM" | bc)
DINT_AVERAGE_BIT=$(echo "scale=3;$TOTAL_DINT_BW/$TOTAL_INTPACKET_NUM" | bc)
bit_ratio=$(echo "scale=3;$DINT_AVERAGE_BIT/$INTPATH_AVERAGE_BIT" | bc)
echo average bit of INT-Path is $INTPATH_AVERAGE_BIT bits
echo average bit of DeltaINT is $DINT_AVERAGE_BIT bis

# Metric 3: INT-packet num
TOTAL_INTPACKET_NUM_PPS=$(echo "scale=3;$TOTAL_INTPACKET_NUM/10" | bc)
echo Both INT-packet number of INT-Path and DINT is $TOTAL_INTPACKET_NUM_PPS pps 
