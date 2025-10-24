# Certificate Inventory Scanner for CI

A Python-based certificate monitoring system that scans SSL certificates of listed hosts and fails the CI pipeline if any certificate is near expiry.

## Features

- 🔍 Scans SSL certificates for multiple hosts
- ⚠️ Configurable warning threshold (default: 30 days)
- 📊 Generates CSV reports with certificate details
- 🚨 Fails CI pipeline on expired or near-expiry certificates
- 📈 GitHub Actions integration with artifact uploads
- 💬 Automatic PR comments with scan results

## Files

- `cert_scanner.py` - Main certificate scanner script
- `hosts.txt` - List of hostnames to scan
- `.github/workflows/cert_scan.yml` - GitHub Actions workflow
- `cert_report.csv` - Generated certificate report (output)

## Usage

### Local Testing

```bash
# Basic scan
python3 cert_scanner.py

# Verbose output
python3 cert_scanner.py --verbose

# Custom hosts file
python3 cert_scanner.py --hosts-file my_hosts.txt

# Custom warning threshold
python3 cert_scanner.py --warning-days 60

# Custom output file
python3 cert_scanner.py --output my_report.csv
```

### Command Line Options

- `--hosts-file`: File containing hostnames (default: hosts.txt)
- `--output`: Output CSV file (default: cert_report.csv)
- `--warning-days`: Days before expiry to warn (default: 30)
- `--verbose`: Enable verbose output

### Exit Codes

- `0`: All certificates are valid
- `2`: One or more certificates are expired or near expiry

## GitHub Actions

The workflow runs on:
- Push to main/master branches
- Pull requests to main/master branches

Features:
- Automatic certificate scanning
- CSV report artifact upload
- PR comments with scan results
- Pipeline failure on certificate issues

## CSV Report Format

| Column | Description |
|--------|-------------|
| host | Hostname that was scanned |
| subject | Certificate subject (Common Name) |
| issuer | Certificate issuer (Common Name) |
| days_to_expiry | Days until certificate expires |
| status | Certificate status (valid, expired, error, etc.) |

## Example Output

```
🔍 Starting Certificate Inventory Scanner...
📁 Reading hosts from: hosts.txt
⚠️  Warning threshold: 30 days
📊 Output file: cert_report.csv
--------------------------------------------------
Found 5 hosts to scan
[1/5] Scanning google.com...
  ✅ Valid: 61 days remaining
[2/5] Scanning github.com...
  ✅ Valid: 104 days remaining
[3/5] Scanning stackoverflow.com...
  ✅ Valid: 83 days remaining
[4/5] Scanning microsoft.com...
  ✅ Valid: 156 days remaining
[5/5] Scanning apple.com...
  ✅ Valid: 54 days remaining
Certificate report written to cert_report.csv
--------------------------------------------------
📊 Scan Summary:
   Total hosts: 5
   Valid certificates: 5
   Failed/expiring: 0
✅ All certificates are valid!
```

## Testing with Expired Certificates

To test the failure scenario, you can use `hosts_expired.txt` which includes `expired.badssl.com`:

```bash
python3 cert_scanner.py --hosts-file hosts_expired.txt --verbose
```

This will demonstrate the pipeline failure behavior when expired certificates are detected.

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)
- Network access to scan target hosts
