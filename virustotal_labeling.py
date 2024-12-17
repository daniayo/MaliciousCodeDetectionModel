import os
import time
import hashlib
import requests

API_KEY = '-'
BASE_URL = 'https://www.virustotal.com/api/v3/'

path_dir = './malware_samples'

headers = {
    'x-apikey': API_KEY
}

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_report(file_hash):
    url = f"{BASE_URL}files/{file_hash}"
    response = requests.get(url, headers=headers)
    return response.json()

def req_scan(file_path):
    url = f"{BASE_URL}files"
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, headers=headers, files=files)
    return response.json()

def scan_files_in_directory(path_dir):
    for filename in os.listdir(path_dir):
        file_path = os.path.join(path_dir, filename)

        if not os.path.isfile(file_path):
            continue

        if len(filename) != 32 or not all(c in '0123456789abcdef' for c in filename.lower()):
            md5_hash = calculate_md5(file_path)
        else:
            md5_hash = filename
        
        print(f"Scanning: {file_path} (MD5: {md5_hash})")
        
        report = get_report(md5_hash)
        
        if 'data' not in report:
            print("No analysis result found. Requesting scan.")
            req_scan(file_path)
            time.sleep(20)

            report = get_report(md5_hash)
        
        if 'data' in report:
            detected_count = sum(1 for engine in report['data']['attributes']['last_analysis_results'].values() if engine['category'] == 'malicious')
            print(f"Detected by {detected_count} antivirus engines.")

            new_filename = f"{detected_count}#{md5_hash}"
            new_file_path = os.path.join(path_dir, new_filename)

            os.rename(file_path, new_file_path)
            print(f"Renamed file to: {new_filename}")

        time.sleep(15)

if __name__ == '__main__':
    scan_files_in_directory(path_dir)
