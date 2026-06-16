import os
import sys
import subprocess
import logging

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
# -----------------------------

SIGMA_DIR = "rules/sigma"

def run_pysigma_validation(target_dir=SIGMA_DIR):
    """Runs the official sigma-cli validation against a directory."""
    logger.info(f"Starting pySigma validation on {target_dir}...")
    try:
        result = subprocess.run(['sigma', 'check', target_dir], capture_output=True, text=True)
        if result.returncode != 0:
            errors = result.stdout.splitlines() + result.stderr.splitlines()
            return [e for e in errors if e.strip()]
        return []
    except FileNotFoundError:
        logger.error("sigma-cli is not installed or not in PATH. Run 'pip install sigma-cli'")
        return ["[!] sigma-cli missing"]

def main():
    if not os.path.exists(SIGMA_DIR):
        logger.error(f"Directory {SIGMA_DIR} not found. Exiting.")
        sys.exit(0)
        
    errors = run_pysigma_validation()
    if errors:
        logger.error("CI/CD Pipeline halted. Sigma validation failed:")
        for error in errors:
            logger.error(error)
        sys.exit(1)
    else:
        logger.info("PASSED: All Sigma rules are syntactically valid.")
        sys.exit(0)

if __name__ == "__main__":
    main()
