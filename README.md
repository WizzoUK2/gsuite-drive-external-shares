# GSuite Drive External Shares Scanner

This tool uses GAM to:

- Audit Google Drive files for external sharing
- Optionally remove shares to specified email addresses
- Support both individual users and Workspace-wide scanning
- Log output to both console and file

## Setup

1. Install [GAM](https://github.com/GAM-team/GAM) and authenticate with your Workspace.
2. Install Python 3.7+.

## Usage

```bash
python gam_script.py --user alice@example.com --domain example.com --dry-run

python gam_script.py --workspace --domain example.com --external-users-file external_users.txt --remove
```

The script now prints clearer errors if GAM is missing or not configured.
