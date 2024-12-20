#!/bin/bash

# Define the IP address of the iperf server
SERVER_IP="10.0.1.2"

# Define the output file for the results
OUTPUT_FILE="iperf_results_with_16.txt"

# Initialize the output file
echo "Running iperf test 100 times..." > $OUTPUT_FILE

# Run the test 50 times
for i in {1..100}
do
    echo "Running iperf test $i..." >> $OUTPUT_FILE
    # Run the iperf client command (adjust parameters as needed)
    iperf -c $SERVER_IP -t 10 -i 1 >> $OUTPUT_FILE
    echo "Test $i completed." >> $OUTPUT_FILE
done

echo "Experiment completed. Results saved in $OUTPUT_FILE"
