```
# DNS and Malware Hash Query Script

## Overview

This script is designed to facilitate the querying of DNS records and checking hash information in malware databases. It allows users to gather DNS records for a specified domain and look up file hashes in various malware databases.

## Features

- Look up file hashes (MD5, SHA1, SHA256) in DShield and Cymru databases.
- Save gathered information to a timestamped output file.

## Prerequisites

1. Ensure you have `dig` and `perl` installed on your system.
   - You can install `dig` with tools like `bind-utils` on CentOS or `dnsutils` on Ubuntu.
   - Perl is usually pre-installed on Unix-like systems.

## Hash Checking Resources

After gathering hashes, you may want to verify them or see if they are known malicious indicators. Here are some online resources you can use to check hashes:

1. https://www.virustotal.com/ - Submit files or hashes to see if they are flagged by antivirus engines.
2. https://www.hybrid-analysis.com/ - Analyze files and URLs; submit hashes for known associations.
3. https://malshare.com/ - Access to malware samples and known hash information.
4. https://www.onlinehashcrack.com/ - Check hashes against known databases and attempt cracking them.
5. https://hashlookup.io/ - Search for hashes and get detailed information on their origins.

## Output

All gathered information will be saved to a timestamped text file, which includes DNS records, hash queries, and their types.
```
