import os
import subprocess
import sys
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

def run_pysigma_validation():
    logger.info("Starting pySigma validation...")
    
    if not os.path.exists(SIGMA_DIR):
        logger.error(f"Directory '{SIGMA_DIR}' not found.")
        return False

    try:
        result = subprocess.run(
            ["sigma", "check", SIGMA_DIR],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("Validation passed. All Sigma rules are syntactically correct.")
            return True
        else:
            logger.error("Validation failed. Fix the Sigma syntax errors below:")
            # We keep standard print() here specifically to preserve the raw formatted output from the sigma-cli tool
            print(result.stdout) 
            print(result.stderr)
            return False
            
    except FileNotFoundError:
        logger.error("sigma-cli is not installed or not in PATH. Run 'pip install sigma-cli'")
        return False

if __name__ == "__main__":
    success = run_pysigma_validation()
    if not success:
        sys.exit(1)
    sys.exit(0)
