```
# DNS and Malware Hash Query Script

## Overview

This script is designed to facilitate the querying of DNS records and checking hash information in malware databases. It allows users to gather DNS records for a specified domain and look up file hashes in various malware databases.

## Features

- Query DNS records (A, AAAA, MX, etc.) for a specified domain.
- Look up file hashes (MD5, SHA1, SHA256) in DShield and Cymru databases.
- Save gathered information to a timestamped output file.

## Prerequisites

1. Ensure you have `dig` and `perl` installed on your system.
   - You can install `dig` with tools like `bind-utils` on CentOS or `dnsutils` on Ubuntu.
   - Perl is usually pre-installed on Unix-like systems.

## Usage

The script accepts the following arguments:

```bash
./gethash.sh [-a hash_algorithm] [-v level] <domain> [type] [-h <hash>]
```

### Options:

- `-a hash_algorithm`: Specify the hash algorithm (`sha256`, `md5`, or `sha1`). Default is `sha256`.
- `-v level`: Set verbosity level (`0`: none, `1`: info, `2`: verbose). Default is `0`.
- `-h <hash>`: Query DShield and Cymru databases for the given hash (optional).
- `<domain>`: The domain you want to query for DNS records.
- `[type]`: The type of DNS record to query (`A`, `AAAA`, `MX`, etc.). Default is `A`.

### Example Commands:

- Query A records for `example.com`:
  ```bash
  ./gethash.sh example.com
  ```

- Query hash information for a given MD5 hash:
  ```bash
  ./gethash.sh -h d41d8cd98f00b204e9800998ecf8427e
  ```

## Hash Checking Resources

After gathering hashes, you may want to verify them or see if they are known malicious indicators. Here are some online resources you can use to check hashes:

1. **[VirusTotal](https://www.virustotal.com/)** - Submit files or hashes to see if they are flagged by antivirus engines.
2. **[Hybrid Analysis](https://www.hybrid-analysis.com/)** - Analyze files and URLs; submit hashes for known associations.
3. **[Malshare](https://malshare.com/)** - Access to malware samples and known hash information.
4. **[OnlineHashCrack](https://www.onlinehashcrack.com/)** - Check hashes against known databases and attempt cracking them.
5. **[Hashlookup](https://hashlookup.io/)** - Search for hashes and get detailed information on their origins.

## Output

All gathered information will be saved to a timestamped text file, which includes DNS records, hash queries, and their types.
```
