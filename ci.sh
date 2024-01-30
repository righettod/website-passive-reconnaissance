#!/bin/bash
############################################################
# Script to perform the "Continuous Integration" validation
############################################################
# Define the output file destination
OUT=/tmp/out-$RANDOM-$RANDOM.tmp
echo "OUT set to file: $OUT."
# Execute the script
python wpr.py -d righettod.eu -s -n 8.8.8.8 -t 30 > $OUT
# Validate the execution
marker=$(grep -Fc "Reconnaissance finished" $OUT)
echo "Marker occurences found into the OUT file: $marker."
rm $OUT
if [ $marker -eq 0 ]
then
    exit -1
else
    exit 0
fi
