import tkinter as tk
from tkinter import ttk
import psutil
import winreg
import datetime
import os
from collections import defaultdict

class AppUsageAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("App Usage Analyzer")
        self.geometry("800x600")
        
        # Dictionary to store app usage data
        self.app_usage = defaultdict(lambda: {
            'last_used': None,
            'total_runtime': 0,
            'size': 0
        })

        self.create_gui()
        self.start_monitoring()

    def create_gui(self):
        # Create main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create treeview
        columns = ('App Name', 'Last Used', 'Total Runtime', 'Size', 'Location')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings')

        # Set column headings and enable sorting
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
            self.tree.column(col, width=150)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Add buttons frame
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        # Add refresh button
        refresh_btn = ttk.Button(button_frame, text="Refresh", command=self.refresh_data)
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Add status label
        self.status_label = ttk.Label(self, text="")
        self.status_label.pack(pady=5)

    def sort_treeview(self, col):
        """Sort treeview contents when a column header is clicked"""
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        l.sort(reverse=self.tree.heading(col).get('reverse', False))

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        # Reverse sort next time
        self.tree.heading(col, reverse=not self.tree.heading(col).get('reverse', False))

    def get_installed_apps(self):
        apps = []
        
        # Windows Registry paths for installed applications
        paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]

        for path in paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                            if location:  # Only add if location is not empty
                                apps.append((name, location))
                        except (WindowsError, KeyError):
                            continue
                        finally:
                            winreg.CloseKey(subkey)
                    except WindowsError:
                        continue
                winreg.CloseKey(key)
            except WindowsError:
                continue
        return apps

    def get_app_size(self, path):
        total_size = 0
        if path and os.path.exists(path):
            try:
                for dirpath, dirnames, filenames in os.walk(path):
                    for f in filenames:
                        try:
                            fp = os.path.join(dirpath, f)
                            if os.path.exists(fp):  # Check if file exists
                                total_size += os.path.getsize(fp)
                        except (OSError, FileNotFoundError):
                            continue  # Skip files that can't be accessed
            except (OSError, PermissionError):
                pass  # Skip directories that can't be accessed
        return total_size / (1024 * 1024)  # Convert to MB

    def start_monitoring(self):
        def monitor():
            for proc in psutil.process_iter(['name', 'create_time']):
                try:
                    name = proc.info['name']
                    create_time = datetime.datetime.fromtimestamp(proc.info['create_time'])
                    
                    if name not in self.app_usage or not self.app_usage[name]['last_used']:
                        self.app_usage[name]['last_used'] = create_time
                    else:
                        self.app_usage[name]['last_used'] = max(
                            create_time,
                            self.app_usage[name]['last_used']
                        )
                    
                    self.app_usage[name]['total_runtime'] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            self.after(60000, monitor)  # Update every minute
        
        monitor()

    def refresh_data(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.status_label.config(text="Refreshing data...")
        self.update()

        try:
            # Get installed apps
            installed_apps = self.get_installed_apps()

            # Update tree
            for app_name, location in installed_apps:
                try:
                    size = self.get_app_size(location)
                    usage_data = self.app_usage.get(app_name, {
                        'last_used': None,
                        'total_runtime': 0,
                        'size': size
                    })

                    last_used = usage_data['last_used'].strftime('%Y-%m-%d %H:%M:%S') if usage_data['last_used'] else 'Never'
                    total_runtime = f"{usage_data['total_runtime']} minutes"

                    self.tree.insert('', tk.END, values=(
                        app_name,
                        last_used,
                        total_runtime,
                        f"{size:.2f} MB",
                        location
                    ))
                except Exception as e:
                    print(f"Error processing {app_name}: {str(e)}")
                    continue

            self.status_label.config(text="Data refresh completed")
        except Exception as e:
            self.status_label.config(text=f"Error refreshing data: {str(e)}")

if __name__ == "__main__":
    app = AppUsageAnalyzer()
    app.mainloop()