import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import winreg
import os
import subprocess
import json
import hashlib
from collections import defaultdict
import threading
from datetime import datetime
import psutil
import winapps
import sys

class DuplicateAppUninstaller(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Duplicate App Uninstaller")
        self.geometry("1200x800")
        
        # Store app data
        self.apps_data = {}
        self.duplicate_groups = []
        self.scanning = False
        
        self.create_gui()
        # Automatically refresh app list on startup
        self.after(1000, self.refresh_app_list)

    def create_gui(self):
        # Main container
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create app list panel
        list_frame = ttk.LabelFrame(main_container, text="Installed Applications")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create treeview for apps
        columns = ('Name', 'Version', 'Publisher', 'Install Date', 'Size', 'Install Location', 'Source')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='tree headings')
        
        # Configure columns
        self.tree.column('#0', width=30)
        column_widths = {
            'Name': 200,
            'Version': 100,
            'Publisher': 150,
            'Install Date': 100,
            'Size': 100,
            'Install Location': 300,
            'Source': 100
        }
        
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=column_widths.get(col, 100))

        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

        # Pack scrollbars and tree
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Control panel
        control_panel = ttk.Frame(self)
        control_panel.pack(fill=tk.X, padx=10, pady=5)

        # Add buttons
        ttk.Button(control_panel, text="Scan for Duplicates", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_panel, text="Uninstall Selected", command=self.uninstall_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_panel, text="Refresh List", command=self.refresh_app_list).pack(side=tk.LEFT, padx=5)
        
        # Progress bar and status
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(control_panel, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.status_label = ttk.Label(control_panel, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)

        # Filter frame
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self.apply_filter)
        ttk.Entry(filter_frame, textvariable=self.filter_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Uninstall", command=self.uninstall_selected)
        self.context_menu.add_command(label="Open Location", command=self.open_location)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Path", command=self.copy_path)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.show_app_details)

    def apply_filter(self, *args):
        """Apply filter to the app list"""
        filter_text = self.filter_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        
        if not self.apps_data:
            return
            
        for name, data in self.apps_data.items():
            try:
                # Check if filter text matches any of the searchable fields
                if (filter_text in name.lower() or 
                    filter_text in data.get('publisher', '').lower() or 
                    filter_text in data.get('version', '').lower() or 
                    filter_text in data.get('install_location', '').lower()):
                    
                    # Calculate size
                    size = self.calculate_app_size(data.get('install_location', ''))
                    size_str = f"{size / 1024 / 1024:.2f} MB" if size > 0 else "Unknown"
                    
                    # Insert matching item
                    self.tree.insert('', 'end', values=(
                        name,
                        data.get('version', 'Unknown'),
                        data.get('publisher', 'Unknown'),
                        'Unknown',  # Install date
                        size_str,
                        data.get('install_location', ''),
                        data.get('source', 'Unknown')
                    ))
            except Exception as e:
                print(f"Error filtering app {name}: {str(e)}")
                continue

    def get_installed_apps(self):
        """Gather installed applications from multiple sources"""
        apps = {}
        
        # Get apps from Windows Registry
        def get_reg_apps(reg_path, reg_key=winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(reg_key, reg_path) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    # Only add apps that have a DisplayName
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    if name and name.strip():
                                        data = {
                                            'name': name,
                                            'version': 'Unknown',
                                            'publisher': 'Unknown',
                                            'install_location': '',
                                            'uninstall_string': '',
                                            'source': 'Registry'
                                        }
                                        
                                        # Try to get additional information
                                        try:
                                            data['version'] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                        except: pass
                                        
                                        try:
                                            data['publisher'] = winreg.QueryValueEx(subkey, "Publisher")[0]
                                        except: pass
                                        
                                        try:
                                            data['install_location'] = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                        except: pass
                                        
                                        try:
                                            data['uninstall_string'] = winreg.QueryValueEx(subkey, "UninstallString")[0]
                                        except: pass
                                        
                                        apps[name] = data
                                except Exception as e:
                                    print(f"Error processing registry key: {str(e)}")
                            i += 1
                        except WindowsError:
                            break
            except WindowsError as e:
                print(f"Error accessing registry path {reg_path}: {str(e)}")

        # Check both 32 and 64 bit registry
        get_reg_apps(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        get_reg_apps(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")

        # Get Windows Store apps
        try:
            for app in winapps.list_installed():
                if app.name and app.name.strip():
                    apps[app.name] = {
                        'name': app.name,
                        'version': getattr(app, 'version', 'Unknown'),
                        'publisher': getattr(app, 'publisher', 'Unknown'),
                        'install_location': getattr(app, 'install_location', ''),
                        'uninstall_string': '',
                        'source': 'Windows Store'
                    }
        except Exception as e:
            print(f"Error getting Windows Store apps: {str(e)}")

        return apps

    def calculate_app_size(self, install_location):
        """Calculate the size of an installed application"""
        total_size = 0
        if install_location and os.path.exists(install_location):
            try:
                for dirpath, dirnames, filenames in os.walk(install_location):
                    for f in filenames:
                        try:
                            fp = os.path.join(dirpath, f)
                            if os.path.exists(fp):
                                total_size += os.path.getsize(fp)
                        except (OSError, FileNotFoundError):
                            continue
            except (OSError, PermissionError):
                pass
        return total_size

    def refresh_app_list(self):
        """Refresh the list of installed applications"""
        self.status_label.config(text="Refreshing app list...")
        self.progress_var.set(0)
        self.tree.delete(*self.tree.get_children())
        
        def refresh():
            try:
                self.apps_data = self.get_installed_apps()
                total_apps = len(self.apps_data)
                
                if total_apps == 0:
                    self.status_label.config(text="No applications found")
                    return
                    
                for i, (name, data) in enumerate(self.apps_data.items()):
                    try:
                        size = self.calculate_app_size(data['install_location'])
                        size_str = f"{size / 1024 / 1024:.2f} MB" if size > 0 else "Unknown"
                        
                        self.tree.insert('', 'end', values=(
                            name,
                            data.get('version', 'Unknown'),
                            data.get('publisher', 'Unknown'),
                            'Unknown',  # Install date
                            size_str,
                            data.get('install_location', ''),
                            data.get('source', 'Unknown')
                        ))
                        
                        progress = ((i + 1) / total_apps) * 100
                        self.progress_var.set(progress)
                        self.status_label.config(text=f"Processed {i + 1} of {total_apps} apps")
                        self.update_idletasks()
                    except Exception as e:
                        print(f"Error processing app {name}: {str(e)}")
                        continue
                    
                self.status_label.config(text=f"Found {total_apps} applications")
            except Exception as e:
                self.status_label.config(text=f"Error refreshing app list: {str(e)}")
                messagebox.showerror("Error", f"Failed to refresh app list: {str(e)}")
            finally:
                self.progress_var.set(0)
        
        threading.Thread(target=refresh, daemon=True).start()

    def sort_column(self, col):
        """Sort treeview column"""
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            # Try to sort numerically for size column
            if col == 'Size':
                l.sort(key=lambda t: float(t[0].split()[0]) if t[0] != "Unknown" else -1)
            else:
                l.sort()
        except ValueError:
            l.sort()  # Fall back to string sort

        # Rearrange items in sorted positions
        for index, (_, k) in enumerate(l):
            self.tree.move(k, '', index)

    def start_scan(self):
        """Start scanning for duplicate applications"""
        if not self.apps_data:
            messagebox.showinfo("Info", "No applications found to scan")
            return
            
        self.scanning = True
        threading.Thread(target=self.scan_for_duplicates, daemon=True).start()

    def scan_for_duplicates(self):
        """Scan for duplicate applications"""
        self.status_label.config(text="Scanning for duplicates...")
        self.progress_var.set(0)
        
        # Reset previous duplicate markings
        for item in self.tree.get_children():
            self.tree.item(item, tags=())

        # Group by similar names
        name_groups = defaultdict(list)
        total_apps = len(self.apps_data)
        
        for i, (name, data) in enumerate(self.apps_data.items()):
            # Create a simplified name for comparison
            simple_name = ''.join(c.lower() for c in name if c.isalnum())
            name_groups[simple_name].append(name)
            
            progress = ((i + 1) / total_apps) * 100
            self.progress_var.set(progress)
            self.status_label.config(text=f"Analyzing {i + 1} of {total_apps}")
            self.update_idletasks()

        # Find duplicates
        self.duplicate_groups = []
        for names in name_groups.values():
            if len(names) > 1:
                self.duplicate_groups.append(names)
        
        # Update the tree view to highlight duplicates
        self.tree.tag_configure('duplicate', background='light yellow')
        for group in self.duplicate_groups:
            for name in group:
                for item in self.tree.get_children():
                    if self.tree.item(item)['values'][0] == name:
                        self.tree.item(item, tags=('duplicate',))
        
        self.status_label.config(text=f"Found {len(self.duplicate_groups)} duplicate groups")
        self.progress_var.set(0)
        self.scanning = False

        if len(self.duplicate_groups) == 0:
            messagebox.showinfo("Scan Complete", "No duplicate applications found")
        else:
            messagebox.showinfo("Scan Complete", f"Found {len(self.duplicate_groups)} groups of duplicate applications")

    def uninstall_selected(self):
        """Uninstall selected applications"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "Please select applications to uninstall")
            return

        apps_to_uninstall = [self.tree.item(item)['values'][0] for item in selected_items]
        if messagebox.askyesno("Confirm Uninstall", 
                              f"Are you sure you want to uninstall these applications?\n\n{chr(10).join(apps_to_uninstall)}"):
            for item in selected_items:
                app_name = self.tree.item(item)['values'][0]
                app_data = self.apps_data.get(app_name)
                if app_data:
                    try:
                        if app_data['source'] == 'Windows Store':
                            subprocess.run(['powershell', 'Get-AppxPackage', f"*{app_name}*", '|', 'Remove-AppxPackage'])
                        else:
                            uninstall_string = app_data.get('uninstall_string', '')
                            if uninstall_string:
                                if 'msiexec' in uninstall_string.lower():
                                    subprocess.run(uninstall_string, shell=True)
                                else:
                                    subprocess.run(f'{uninstall_string} /SILENT', shell=True)
                            else:
                                messagebox.showerror("Error", f"No uninstall command found for {app_name}")
                                continue
                        
                        self.tree.delete(item)
                        del self.apps_data[app_name]
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to uninstall {app_name}: {str(e)}")

    def show_context_menu(self, event):
        """Show context menu"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def show_app_details(self, event):
        """Show detailed information about the selected application"""
        item = self.tree.selection()[0]
        app_name = self.tree.item(item)['values'][0]
        app_data = self.apps_data.get(app_name)
        
        if app_data:
            details = "\n".join([f"{k}: {v}" for k, v in app_data.items()])
            messagebox.showinfo("App Details", details)

    def open_location(self):
        """Open the installation location of the selected application"""
        item = self.tree.selection()[0]
        location = self.tree.item(item)['values'][5]  # Install Location column
        if location and os.path.exists(location):
            os.startfile(location)
        else:
            messagebox.showinfo("Info", "Installation location not available or invalid")

    def copy_path(self):
        """Copy the installation path to clipboard"""
        item = self.tree.selection()[0]
        location = self.tree.item(item)['values'][5]  # Install Location column
        self.clipboard_clear()
        self.clipboard_append(location)

if __name__ == "__main__":
    app = DuplicateAppUninstaller()
    app.mainloop()