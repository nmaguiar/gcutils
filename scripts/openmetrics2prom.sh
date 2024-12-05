#!/bin/bash

# Check if the file exists
if [ ! -f $1 ]; then
  echo "File not found!"
  exit 1
fi

# Check if /usr/share/prometheus/data exists
if [ ! -d /usr/share/prometheus/data ]; then
  echo "Prometheus directory not found! Run 'start_prom_graf.sh' first."
  exit 1
fi

# If '# EOF' is not present in the file, the script will fail
# This is a simple check to ensure the file is not empty
if ! grep -q '# EOF' $1; then
  echo "# EOF" >> $1
fi

# Create the blocks
sed -i '/ NaN [0-9]\+$/d' $1
sudo -u prometheus promtool tsdb create-blocks-from openmetrics $1 /usr/share/prometheus/data