# NTDS Report

`ntds_report.py` generates statistics from cracked NTLM hashes and optionally an NTDS dump. It prints the results and stores them in a report file.

## Usage

```bash
python3 ntds_report.py CRACKED.TXT [NTDS.DMP] [-o output.txt]
```

- `CRACKED.TXT` should contain lines in the form `NTLM_HASH:password`.
- `NTDS.DMP` is optional and can be a `secretsdump`/`pwdump` style file to compute the cracking percentage.
- The report is written to `output.txt` (default `report.txt`).

## Example

```bash
echo "HASH:Password1" > cracked.txt
python3 ntds_report.py cracked.txt
```

The script will print a summary and create `report.txt` with the same content.
