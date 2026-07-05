import glob
import os
import sys
import subprocess
import logging
from typing import List

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

def run_backend_compilability_check(target_dir: str = SIGMA_DIR) -> List[str]:
    """Prove every rule converts through a real pySigma backend (Elasticsearch
    Lucene + sysmon pipeline). The output is discarded -- Wazuh XML comes from
    compile_sigma.py's own AST walker, not this backend -- but a rule no backend
    can compile fails here first, before it ever reaches the custom compiler.
    """
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.pipelines.sysmon import sysmon_pipeline

    logger.info(f"Starting pySigma backend compilability check on {target_dir}...")
    paths = glob.glob(os.path.join(target_dir, "**", "*.yml"), recursive=True)
    paths += glob.glob(os.path.join(target_dir, "**", "*.yaml"), recursive=True)
    if not paths:
        return []
    try:
        collection = SigmaCollection.load_ruleset(sorted(paths))
        LuceneBackend(processing_pipeline=sysmon_pipeline()).convert(collection)
        return []
    except Exception as e:
        return [f"[!] Backend compilability check failed: {type(e).__name__}: {e}"]

if __name__ == "__main__":
    errors = run_pysigma_validation()
    errors += run_backend_compilability_check()
    if errors:
        logger.error("CI/CD Pipeline halted. Sigma validation failed:")
        for err in errors:
            logger.error(err)
        sys.exit(1)
    logger.info("PASSED: All Sigma rules are syntactically valid and backend-compilable.")
