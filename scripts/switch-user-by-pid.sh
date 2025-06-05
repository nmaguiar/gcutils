#!/bin/bash

# Check if the script is executed as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check if the PID argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <PID>"
  exit 1
fi

# Store the PID argument
PID=$1

# Get process details for the given PID (Alpine/BusyBox compatible)
PROCESS_INFO=$(ps -o pid=,user=,group= -p "$PID")

# Check if the process exists
if [ -z "$PROCESS_INFO" ]; then
  echo "No process found with PID $PID"
  exit 1
fi

# Extract the user and group from the process information
USER=$(echo $PROCESS_INFO | awk '{print $2}')
GROUP=$(echo $PROCESS_INFO | awk '{print $3}')

# If the extracted username is numeric, prepend a "u" to avoid invalid user names
if [[ "$USER" =~ ^[0-9]+$ ]]; then
  USER="u$USER"
fi

# If the extracted group is numeric, prepend a "u" to avoid invalid group names
if [[ "$GROUP" =~ ^[0-9]+$ ]]; then
  GROUP="u$GROUP"
fi

# Create the group if it doesn't exist (Alpine/BusyBox)
if ! getent group "$GROUP" > /dev/null 2>&1; then
  sudo addgroup "$GROUP"
fi

# Create the user if it doesn't exist (Alpine/BusyBox)
if ! getent passwd "$USER" > /dev/null 2>&1; then
  sudo adduser -D -G "$GROUP" "$USER"
fi

# Switch to the user and group of the process
echo "Switching to user '$USER' and group '$GROUP' based on process with PID $PID."
sudo -g $GROUP -u $USER -i bash