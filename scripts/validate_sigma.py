import glob
import sys
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

def main():
    print("[*] Starting pySigma validation...")
    
    # Grab all YAML files in the rules directory
    sigma_files = glob.glob('rules/*.yml') + glob.glob('rules/*.yaml')

    if not sigma_files:
        print("[-] No Sigma rules found to validate.")
        sys.exit(0)

    has_errors = False

    for filepath in sigma_files:
        print(f" -> Validating {filepath}...")
        try:
            with open(filepath, 'r') as f:
                rule_content = f.read()
                # This is the engine: pySigma parses the YAML against the official Sigma schema
                SigmaCollection.from_yaml(rule_content)
            print(f"    [+] {filepath} is perfectly formatted.")
        
        except SigmaError as e:
            print(f"    [-] pySigma Error in {filepath}: {e}")
            has_errors = True
        except Exception as e:
            print(f"    [-] System Error processing {filepath}: {e}")
            has_errors = True

    # If any rule failed, exit with status code 1 to intentionally break the GitHub Action
    if has_errors:
        print("\n[-] FATAL: Validation failed. Fix the Sigma syntax errors above.")
        sys.exit(1)
    else:
        print("\n[+] Success: All Sigma rules passed validation.")
        sys.exit(0)

if __name__ == "__main__":
    main()
