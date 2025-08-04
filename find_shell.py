import os
import re
from datetime import datetime

def scan_php_files(start_dir="."):
    patterns = [
        r'eval\s*\(',                     
        r'base64_decode\s*\(',             
        r'chr\s*\(\s*0x[0-9a-f]+\s*\)',    
        r'file_put_contents\s*\(.*,\s*["\'].*eval',  
    ]
    current_date = datetime.now().strftime("%Y-%m-%d")
    log_file = f"{current_date}_out.log"

    with open(log_file, "a") as log:
        log.write(f"\n=== Scan is started at {current_date} ===\n\n")

        for root, dirs, files in os.walk(start_dir):
            for file in files:
                if file.endswith(".php"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for pattern in patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    log.write(f"[{current_time}] Find a malware in: {file_path}\n")
                                    log.write(f"pattern: {pattern}\n\n")
                                    break  
                    except Exception as e:
                        log.write(f"[ERROR] {file_path}: {e}\n")

if __name__ == "__main__":
    scan_php_files("Корень сервака") 