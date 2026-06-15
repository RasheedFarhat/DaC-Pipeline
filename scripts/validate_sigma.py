import glob
import os
import sys
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.exceptions import SigmaError

def validate_sigma_rules(directory):
    """Scans a directory for Sigma rules and validates their syntax."""
    sigma_files = glob.glob(os.path.join(directory, '**', '*.yml'), recursive=True) + \
                  glob.glob(os.path.join(directory, '**', '*.yaml'), recursive=True)

    errors = []
    if not sigma_files:
        return errors

    backend = LuceneBackend()

    for filepath in sigma_files:
        try:
            with open(filepath, 'r') as f:
                rule_content = f.read()
            
            # 1. Validate against Sigma Schema
            collection = SigmaCollection.from_yaml(rule_content)
            
            # 2. Prove it can compile to a backend
            backend.convert(collection)
        
        except SigmaError as e:
            errors.append(f"pySigma Error in {filepath}: {e}")
        except Exception as e:
            errors.append(f"System Error processing {filepath}: {e}")
            
    return errors

def main():
    print("[*] Starting pySigma validation...")
    
    errors = validate_sigma_rules('rules')
    
    if errors:
        print("\n[-] FATAL: Validation failed. Fix the Sigma syntax errors above.")
        for error in errors:
            print(f"    [-] {error}")
        sys.exit(1)
    else:
        print("\n[+] Success: All Sigma rules passed validation.")
        sys.exit(0)

if __name__ == "__main__":
    main()
