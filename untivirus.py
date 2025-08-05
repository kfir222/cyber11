import os
import requests
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext

virus_total_api_key = "66e6eb5507e3f33415b67c192f19f3de0941dd9452da04a3b551998dfd266444"



def start_gui():
    window = tk.Tk()
    window.title("Simple Antivirus")
    window.geometry("600x400")

    output_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=70, height=20)
    output_box.pack(pady=10)

    scan_button = tk.Button(window, text="Select Folder to Scan", command=lambda: choose_folder(output_box))
    scan_button.pack()

    window.mainloop()

def choose_folder(output_box):
    folder = filedialog.askdirectory(title="Select Folder to Scan")
    if folder:
        output_box.insert(tk.END, f"\n📁 Scanning folder: {folder}\n")
        iterate_files(folder, output_box)


def iterate_files(folder_path, output_box):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)

        if os.path.isdir(full_path):
            iterate_files(full_path, output_box)
        else:
            scan_file(full_path, output_box)


def scan_file(file_path, output_box):
    response = upload_file(file_path, output_box)
    scan_id = response.get('scan_id')
    if scan_id:
        is_virus = get_report(scan_id, output_box)
        if is_virus:
            
            output_box.insert(tk.END, "VIRUS DETECTED!!! Filepath: ", file_path)
            output_box.update()
        else:
            
            output_box.insert(tk.END, "{} is not virus".format(file_path))
            output_box.update()
    else:
        
         output_box.insert(tk.END, "Unexpected response, no scan id found for file: ", file_path)
         output_box.update()


def upload_file(file_path, output_box):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        'x-apikey': virus_total_api_key
    }

    with open(file_path, 'rb') as file_content:
        files = {'file': (os.path.basename(file_path), file_content)}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200 or response.status_code == 202:
        result = response.json()
        scan_id = result["data"]["id"]
        return {"scan_id": scan_id}
    else:
        
        output_box.insert(tk.END, "Upload failed. Status code:", response.status_code)
        output_box.update()
        
        output_box.insert(tk.END, "Response:", response.text)
        output_box.update()
        return None



def get_report(scan_id, output_box):
    
    output_box.insert(tk.END, "Getting report for scan id:", scan_id)
    output_box.update()
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    
    headers = {
        'x-apikey': virus_total_api_key
    }

    response = requests.get(url, headers=headers)

    if not response:
        
        output_box.insert(tk.END,"No response received.")
        output_box.update()

        return False

    if response.status_code == 200:
        result = response.json()
        status = result["data"]["attributes"]["status"]
        if status != "completed":
            
            output_box.insert(tk.END, "Scan not completed yet...")
            output_box.update()
            time.sleep(5)
            return get_report(scan_id, output_box)
        else:
            stats = result["data"]["attributes"]["stats"]
            positives = stats["malicious"] > 0
            return positives
    else:
        
        output_box.insert(tk.END, "Unexpected status code:", response.status_code)
        output_box.update()
        return False





if __name__ == "__main__":
    start_gui()