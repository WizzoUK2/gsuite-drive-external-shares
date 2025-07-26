import subprocess
import json
from datetime import datetime
import csv
import os
from pathlib import Path
import logging

EXTERNAL_USERS_FILE = "external_users.txt"
OUTPUT_DIR = "output"
LOG_FILE = f"{OUTPUT_DIR}/scan_log.txt"

def setup_logging():
    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

def run_gam_command(args):
    """Run a GAM command and return output as text"""
    logging.info(f"Running GAM: gam {' '.join(args)}")
    result = subprocess.run(["gam"] + args, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Command failed: {result.stderr}")
        raise RuntimeError(f"Command failed: {result.stderr}")
    return result.stdout

def get_drive_files_for_user(user):
    """Export all Drive file ACLs for a user"""
    output_file = f"{OUTPUT_DIR}/{user}_files.csv"
    run_gam_command(["user", user, "drive", "list", "fields", "id,title,permissions", "to", "csv", output_file])
    return output_file

def get_shared_drive_files():
    """Export all shared drive files and their ACLs"""
    output_file = f"{OUTPUT_DIR}/shared_drives_files.csv"
    run_gam_command(["all", "drives", "show", "filelist", "fields", "id,title,permissions", "to", "csv", output_file])
    return output_file

def is_external(email, domain):
    return not email.endswith(f"@{domain}")

def parse_external_users(filename):
    with open(filename, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}

def process_csv(csv_file, domain, external_users=None, dry_run=True):
    external_count = 0
    removed_count = 0

    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_id = row.get("id")
            title = row.get("title")
            for key in row:
                if key.startswith("permissions.") and ".emailAddress" in key:
                    email = row[key].lower()
                    if is_external(email, domain):
                        external_count += 1
                        logging.info(f"External share found: '{title}' ({file_id}) shared with {email}")
                        if external_users and email in external_users:
                            if dry_run:
                                logging.info(f"[DRY RUN] Would remove {email} from {file_id}")
                            else:
                                logging.info(f"Removing {email} from {file_id}")
                                try:
                                    run_gam_command(["user", "admin", "delete", "drivefileacl", file_id, email])
                                    removed_count += 1
                                except RuntimeError as e:
                                    logging.error(f"Failed to remove {email}: {e}")
    return external_count, removed_count

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", help="Specify user email address to scan")
    parser.add_argument("--workspace", action="store_true", help="Scan all Workspace users and shared drives")
    parser.add_argument("--domain", required=True, help="Your internal domain (e.g., example.com)")
    parser.add_argument("--external-users-file", default=EXTERNAL_USERS_FILE, help="File of external users to remove")
    parser.add_argument("--remove", action="store_true", help="Remove sharing from listed external users")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually remove, just print actions")
    parser.add_argument("--auth-mode", choices=["personal", "service"], default="service", help="Choose auth mode: 'personal' for OAuth flow (opens browser), 'service' for Workspace service account (default)")

    args = parser.parse_args()
    if args.auth_mode == "personal":
        logging.info("Using personal OAuth mode. Running 'gam oauth create'...")
        try:
            run_gam_command(["oauth", "create"])
            logging.info("OAuth authorization completed.")
        except Exception as e:
            logging.error(f"OAuth flow failed: {e}")
            return
    else:
        logging.info("Using service account mode (domain-wide delegation).")
    
    setup_logging()
    logging.info("==== Drive Sharing Scan Started ====")

    external_users = parse_external_users(args.external_users_file)
    script_name = "gsuite-drive-external-shares"
    dry_run = args.dry_run or not args.remove

    if args.user:
        try:
            csv_file = get_drive_files_for_user(args.user)
            checked, removed = process_csv(csv_file, args.domain, external_users, dry_run=dry_run)
            write_run_log(script_name, "success", args.user, args.domain, dry_run, checked, removed)
        except Exception as e:
            logging.error(f"Error processing user {args.user}: {e}")
            write_run_log(script_name, "error", args.user, args.domain, dry_run, 0, 0)

    if args.workspace:
        users_csv = f"{OUTPUT_DIR}/users.csv"
        run_gam_command(["print", "users", "to", "csv", users_csv])
        with open(users_csv, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                user = row["primaryEmail"]
                logging.info(f"\n--- Processing {user} ---")
                try:
                    user_csv = get_drive_files_for_user(user)
                    checked, removed = process_csv(user_csv, args.domain, external_users, dry_run=dry_run)
                    write_run_log(script_name, "success", user, args.domain, dry_run, checked, removed)
                except Exception as e:
                    logging.error(f"Error processing user {user}: {e}")
                    write_run_log(script_name, "error", user, args.domain, dry_run, 0, 0)

        logging.info("\n--- Processing Shared Drives ---")
        try:
            shared_csv = get_shared_drive_files()
            checked, removed = process_csv(shared_csv, args.domain, external_users, dry_run=dry_run)
            write_run_log(script_name, "success", "shared_drives", args.domain, dry_run, checked, removed)
        except Exception as e:
            logging.error(f"Error processing shared drives: {e}")
            write_run_log(script_name, "error", "shared_drives", args.domain, dry_run, 0, 0)

    logging.info("==== Drive Sharing Scan Completed ====")

def write_run_log(script_name, status, user, domain, dry_run, checked, removed):
    log_entry = {
        "script": script_name,
        "run_at": datetime.utcnow().isoformat() + "Z",
        "status": status,
        "user": user,
        "domain": domain,
        "dry_run": dry_run,
        "external_users_checked": checked,
        "external_users_removed": removed
    }
    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    with open(f"{OUTPUT_DIR}/runlog.jsonl", "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")


if __name__ == "__main__":
    main()

