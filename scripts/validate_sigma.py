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

SIGMA_DIR = "rules/sigma"

def get_sigma_binary() -> str:
    """Finds sigma-cli relative to the current Python executable."""
    python_bin_dir = os.path.dirname(sys.executable)
    sigma_path = os.path.join(python_bin_dir, 'sigma')
    if os.path.isfile(sigma_path):
        return sigma_path
    raise FileNotFoundError(f"sigma-cli not found in {python_bin_dir}. Run 'pip install sigma-cli'")

def run_pysigma_validation(target_dir=SIGMA_DIR):
    """Runs the official sigma-cli validation against a directory."""
    logger.info(f"Starting pySigma validation on {target_dir}...")
    try:
        sigma_bin = get_sigma_binary()
        result = subprocess.run([sigma_bin, 'check', target_dir], capture_output=True, text=True)
        if result.returncode != 0:
            errors = [line for line in result.stdout.splitlines() + result.stderr.splitlines() if line.strip()]
            return errors
        return []
    except FileNotFoundError as e:
        logger.error(str(e))
        return ["[!] sigma-cli missing"]

if __name__ == "__main__":
    errors = run_pysigma_validation()
    if errors:
        logger.error("CI/CD Pipeline halted. Sigma validation failed:")
        for err in errors:
            logger.error(err)
        sys.exit(1)
    logger.info("PASSED: All Sigma rules are syntactically valid.")
