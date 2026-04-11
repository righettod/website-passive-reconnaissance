#!/bin/bash
############################################################
# Script to perform the "Continuous Integration" validation
############################################################
# Define the output file destination
OUT=/tmp/out-$RANDOM-$RANDOM.tmp
echo "[+] OUT set to file: $OUT."
# Execute the script
cd src/wpr
uv run main.py -d righettod.eu > $OUT
# Validate the execution
marker=$(grep -Fc "Reconnaissance finished" $OUT)
echo "[+] Marker occurences found into the OUT file: $marker."
echo "[+] OUT file content:"
cat $OUT
rm $OUT
if [ $marker -eq 0 ]
then
    echo "[X] Validation failed!"
    exit -1
else
    echo "[V] Validation succeed."
    exit 0
fi
