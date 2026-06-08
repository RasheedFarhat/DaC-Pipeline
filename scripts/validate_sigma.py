import glob
import sys
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.exceptions import SigmaError

def main():
    print("[*] Starting pySigma validation...")
    
    # Grab all YAML files recursively
    sigma_files = glob.glob('rules/**/*.yml', recursive=True) + \
                  glob.glob('rules/**/*.yaml', recursive=True)

    if not sigma_files:
        print("[-] No Sigma rules found to validate.")
        sys.exit(0)

    has_errors = False
    backend = LuceneBackend()

    for filepath in sigma_files:
        print(f" -> Validating {filepath}...")
        try:
            with open(filepath, 'r') as f:
                rule_content = f.read()
            
            # 1. Validate against Sigma Schema
            collection = SigmaCollection.from_yaml(rule_content)
            
            # 2. Prove it can compile to a backend (Lucene)
            backend.convert(collection)
            
            print(f"    [+] {filepath} is perfectly formatted and compilable.")
        
        except SigmaError as e:
            print(f"    [-] pySigma Error in {filepath}: {e}")
            has_errors = True
        except Exception as e:
            print(f"    [-] System Error processing {filepath}: {e}")
            has_errors = True

    if has_errors:
        print("\n[-] FATAL: Validation failed. Fix the Sigma syntax errors above.")
        sys.exit(1)
    else:
        print("\n[+] Success: All Sigma rules passed validation.")
        sys.exit(0)

if __name__ == "__main__":
    main()

