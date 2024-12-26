#!/bin/bash

# Enable debugging mode to see commands being executed (for troubleshooting).
set -x 

# Function to display usage
usage() {
    echo "Welcome to the DNS and Malware Hash Query Script!"
    echo "This script helps you query DNS records and check hash information in malware databases."
    echo "Usage: $0 [-a hash_algorithm] [-v level] <domain> [type] [-h <hash>]"
    echo "Options:"
    echo "  -a hash_algorithm   Specify the hash algorithm (sha256, md5, sha1). Default is sha256."
    echo "  -v level            Set verbosity level (0: none, 1: info, 2: verbose). Default is 0."
    echo "  -h <hash>           Query DShield and Cymru databases for the given hash (optional)."
    echo "  <domain>            The domain you want to query for DNS records."
    echo "  [type]              Type of DNS record to query (A, AAAA, MX, etc.). Default is A."
    echo "Examples:"
    echo "  $0 example.com    # Query A records for example.com"
    echo "  $0 -h d41d8cd98f00b204e9800998ecf8427e     # Query hash info for given MD5 hash"
    exit 1
}

HASH_ALGO="sha256"
VERBOSITY=0
HASH_QUERY=""

# Check for the presence of the 'dig' and 'perl' commands
command -v dig >/dev/null 2>&1 || { echo "Error: 'dig' command not found. Please install 'dig' to use this script."; exit 2; }
command -v perl >/dev/null 2>&1 || { echo "Error: 'perl' command not found. Please install 'perl' to use this script."; exit 2; }

# Parse command-line options
while getopts 'a:v:h:' flag; do
    case "${flag}" in
        a) HASH_ALGO="${OPTARG}" ;;
        v) VERBOSITY="${OPTARG}" ;;
        h) HASH_QUERY="${OPTARG}" ;;
        *) usage ;;
    esac
done

shift $((OPTIND - 1))

# Check if a domain is provided; if not, prompt for one.
if [ "$#" -lt 1 ]; then
    read -p "Please enter the domain to query: " DOMAIN
else
    DOMAIN=$1
fi

# Default record type
RECORD_TYPE=${2:-A}  # Default to A records if not provided

# Validate the hash algorithm
if [[ "$HASH_ALGO" != "sha256" && "$HASH_ALGO" != "md5" && "$HASH_ALGO" != "sha1" ]]; then
    echo "Error: Unsupported hash algorithm: $HASH_ALGO. Please use sha256, md5, or sha1."
    exit 3
fi

# Initialize output content
OUTPUT_CONTENT=""

# Query hash databases if a hash is provided
if [ -n "$HASH_QUERY" ]; then
    # Validate hash based on algorithm length
    case "$HASH_ALGO" in
        sha256) VALID_HASH_REGEX="^[a-f0-9]{64}$" ;;
        md5)    VALID_HASH_REGEX="^[a-f0-9]{32}$" ;;
        sha1)   VALID_HASH_REGEX="^[a-f0-9]{40}$" ;;
    esac

    if ! [[ "$HASH_QUERY" =~ $VALID_HASH_REGEX ]]; then
        echo "Error: Invalid $HASH_ALGO hash format: $HASH_QUERY"
        exit 4
    fi

    # Query the hash database
    if [ "$VERBOSITY" -ge 1 ]; then
        echo "Looking up hash $HASH_QUERY in databases..."
    fi

    # Query DShield
    HASH_DSHIELD_OUTPUT=$(dig +short "${HASH_QUERY}.${HASH_ALGO}.dshield.org" TXT 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$HASH_DSHIELD_OUTPUT" ]; then
        echo "DShield Database result for $HASH_QUERY: $HASH_DSHIELD_OUTPUT"
        OUTPUT_CONTENT+="DShield Database result for $HASH_QUERY: $HASH_DSHIELD_OUTPUT\n"
    else
        OUTPUT_CONTENT+="No results found in the DShield hash database for $HASH_QUERY.\n"
    fi

    # Query Cymru
    HASH_CYMRU_OUTPUT=$(dig +short "${HASH_QUERY}.${HASH_ALGO}.malware.hash.cymru.com" TXT 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$HASH_CYMRU_OUTPUT" ]; then
        echo "Cymru Database result for $HASH_QUERY: $HASH_CYMRU_OUTPUT"
        OUTPUT_CONTENT+="Cymru Database result for $HASH_QUERY: $HASH_CYMRU_OUTPUT\n"
        LAST_SEEN_TIMESTAMP=$(echo "$HASH_CYMRU_OUTPUT" | awk '{print $1}')
        AV_DETECTION_RATE=$(echo "$HASH_CYMRU_OUTPUT" | awk '{print $2}')
        READABLE_TIMESTAMP=$(perl -e "print scalar localtime($LAST_SEEN_TIMESTAMP), \"\n\"")
        OUTPUT_CONTENT+="Last Seen: $READABLE_TIMESTAMP\n"
        OUTPUT_CONTENT+="AV Detection Rate: $AV_DETECTION_RATE\n"
    else
        OUTPUT_CONTENT+="No results found in the Cymru malware hash database for $HASH_QUERY.\n"
    fi
    
    # Append hash algorithm information
    OUTPUT_CONTENT+="Hash Type: $HASH_ALGO\n"
fi

# Validate the domain format
if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "Error: Invalid domain format: $DOMAIN"
    exit 5
fi

# Perform DNS lookup
if [ "$VERBOSITY" -ge 1 ]; then
    echo "Looking up $RECORD_TYPE records for $DOMAIN..."
fi

DNS_OUTPUT=$(dig +short "$DOMAIN" "$RECORD_TYPE" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "Error: Unable to query $DOMAIN for record type $RECORD_TYPE."
    exit 6
fi

if [ -z "$DNS_OUTPUT" ]; then
    OUTPUT_CONTENT+="No DNS records found for domain $DOMAIN.\n"
else
    OUTPUT_CONTENT+="DNS records for $DOMAIN:\n$DNS_OUTPUT\n"

    # Hash the DNS output if a hash algorithm is specified
    case "$HASH_ALGO" in
        sha256) HASH=$(echo "$DNS_OUTPUT" | sha256sum | awk '{print $1}') ;;
        md5)    HASH=$(echo "$DNS_OUTPUT" | md5sum | awk '{print $1}') ;;
        sha1)   HASH=$(echo "$DNS_OUTPUT" | sha1sum | awk '{print $1}') ;;
    esac

    OUTPUT_CONTENT+="Hash of the DNS records for $DOMAIN: $HASH\n"
    OUTPUT_CONTENT+="Hash Type: $HASH_ALGO\n"  # Include hash type for DNS records
    echo "Hash of the DNS records for $DOMAIN: $HASH"
fi

# Create a timestamp for the output filename
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="hash_$HASH_$TIMESTAMP.txt"

# Save all gathered information to the timestamped file
echo -e "$OUTPUT_CONTENT" > "$OUTPUT_FILE"
echo "All gathered information saved to $OUTPUT_FILE"

# Add a pause feature
echo "Press any key to continue..."
read -n 1 -s

exit 0
