#!/bin/bash
# Author:           Christo Deale                  
# Date  :           2023-09-27            
# rhel9_virustotal: Utility to integrate VirusTotal API & scan specific directory on RHEL 9

# VirusTotal API Key
API_KEY=""                                                                          #Your API Key Goes HERE

# Directory containing files to be scanned
SCAN_DIR="/home/user/directory2bscanned"                                            #Specify which directory to scan

# Email and Password for VirusTotal account
VT_EMAIL="name@domain.com"                                                          #YOUR Virus Total Account Email Goes HERE
VT_PASSWORD="password"                                                              #YOUR Virus Total Account Password Goes HERE

# Directory to store log files
LOG_DIR="/virustotal"

# Create the log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Function to get a VirusTotal API token
get_vt_token() {
  local response
  response=$(curl -s -X POST "https://www.virustotal.com/api/v3/users/signin" \
    -H "x-apikey: $API_KEY" \
    -d "email=$VT_EMAIL&password=$VT_PASSWORD")

  # Extract the API token from the response
  local vt_token
  vt_token=$(echo "$response" | jq -r .data.attributes.token)

  echo "$vt_token"
}

# Function to submit a file for scanning to VirusTotal
submit_file() {
  local file_path="$1"
  local vt_token="$2"

  # Submit the file for scanning
  local response
  response=$(curl -s -X POST "https://www.virustotal.com/api/v3/files" \
    -H "x-apikey: $vt_token" \
    -F "file=@$file_path")

  echo "$response"
}

# Function to retrieve scan results from VirusTotal
get_scan_results() {
  local resource="$1"
  local vt_token="$2"

  # Retrieve scan results for the given resource
  local response
  response=$(curl -s "https://www.virustotal.com/api/v3/analyses/$resource" \
    -H "x-apikey: $vt_token")

  echo "$response"
}

# Main script

# Get the VirusTotal API token
vt_token=$(get_vt_token)

# Loop through files in the specified directory
for file_path in "$SCAN_DIR"/*; do
  # Check if the item is a file (not a directory)
  if [ -f "$file_path" ]; then
    # Submit the file for scanning and capture the resource ID
    response=$(submit_file "$file_path" "$vt_token")
    resource=$(echo "$response" | jq -r .data.id)

    # Wait for the scan to complete (you can adjust the sleep duration)
    sleep 60

    # Retrieve scan results
    results=$(get_scan_results "$resource" "$vt_token")

    # Log the results to a file with the same name as the scanned file
    log_file="$LOG_DIR/$(basename "$file_path")_scan_results.txt"
    echo "$results" > "$log_file"

    echo "Scan results for $file_path logged to $log_file"
  fi
done
