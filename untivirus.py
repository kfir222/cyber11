import os
import requests
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext
import watchdog
from watchdog.events import FileSystemEventHandler

class RealTimeScanHandler(FileSystemEventHandler):
    def __init__(self, output_box):
        self.output_box = output_box

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self.output_box.insert("end", f"\n🆕 New file detected: {file_path}\n")
            self.output_box.update()
            scan_file(file_path, self.output_box)
            
from watchdog.observers import Observer

def start_real_time_watch(folder_path, output_box):
    event_handler = RealTimeScanHandler(output_box)
    observer = Observer()
    observer.schedule(event_handler, path=folder_path, recursive=True)
    observer.start()
    output_box.insert("end", f"\n🔍 Real-time scanning started on: {folder_path}\n")
    output_box.update()

virus_total_api_key = "66e6eb5507e3f33415b67c192f19f3de0941dd9452da04a3b551998dfd266444"

import threading
from tkinter import filedialog

def choose_folder_realtime(output_box):
    folder = filedialog.askdirectory(title="choose a folder to follow then in a real time")
    if folder:
        output_box.insert("end", f"\n⏳ start follow {folder}\n")
        output_box.update()
        threading.Thread(target=start_real_time_watch, args=(folder, output_box), daemon=True).start()




def start_gui():
    window = tk.Tk()
    window.title("Simple Antivirus")
    window.geometry("600x400")

    output_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=70, height=20)
    output_box.pack(pady=10)

    scan_button = tk.Button(window, text="Select Folder to Scan", command=lambda: choose_folder(output_box))
    scan_button.pack()

    window.mainloop()
    realtime_button = tk.Button(window, text="📡 start follow in a real time",command=lambda: choose_folder_realtime(output_box))
    realtime_button.pack()


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
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {
        'x-apikey': virus_total_api_key
    }

    for _ in range(10):  
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            status = result["data"]["attributes"]["status"]

            if status == "completed":
                positives = result["meta"]["file_info"].get("malicious", 0)
                return positives > 0
            else:
                output_box.insert(tk.END, "⏳ Scan not completed yet...\n")
                output_box.update()
                time.sleep(5)
        else:
            output_box.insert(tk.END, f"❌ Failed to get report. Status: {response.status_code}\n")
            output_box.update()
            return False

    output_box.insert(tk.END, "⚠️ Timed out waiting for scan to complete.\n")
    output_box.update()
    return False





if __name__ == "__main__":
    start_gui()
