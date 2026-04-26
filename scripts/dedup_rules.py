import os
import yaml

rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))

def find_yaml_files(directory):
    yaml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yaml') or file.endswith('.yml'):
                yaml_files.append(os.path.join(root, file))
    return yaml_files

def deduplicate():
    files = find_yaml_files(rules_dir)
    seen_ids = set()
    total_deduped = 0

    for filepath in files:
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        modified = False
        new_lines = []
        for line in lines:
            if line.strip().startswith('- id:'):
                rule_id = line.split('- id:', 1)[1].strip()
                original_id = rule_id.strip('"\'')
                
                if original_id in seen_ids:
                    # Deduplicate
                    suffix = 1
                    new_id = f"{original_id}-dup{suffix}"
                    while new_id in seen_ids:
                        suffix += 1
                        new_id = f"{original_id}-dup{suffix}"
                    
                    seen_ids.add(new_id)
                    total_deduped += 1
                    modified = True
                    # Reconstruct line safely maintaining indentation
                    idx = line.find('- id:')
                    new_lines.append(line[:idx] + f"- id: {new_id}\n")
                    print(f"Deduplicated {original_id} -> {new_id} in {os.path.basename(filepath)}")
                else:
                    seen_ids.add(original_id)
                    new_lines.append(line)
            else:
                new_lines.append(line)
                
        if modified:
            with open(filepath, 'w') as f:
                f.writelines(new_lines)

    print(f"Total entries deduplicated: {total_deduped}")

if __name__ == "__main__":
    deduplicate()
