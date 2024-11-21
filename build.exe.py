import PyInstaller.__main__
import sys
import os

# Get the directory containing your script
script_dir = os.path.dirname(os.path.abspath(__file__))

PyInstaller.__main__.run([
    'app.py',  # your main script
    '--name=DuplicateAppUninstaller',  # name of your exe
    '--onefile',  # create a single executable
    '--noconsole',  # don't show console window
    '--icon=app.ico',  # optional: path to icon file
    '--add-data=README.txt;.',  # optional: include additional files
    '--clean',  # clean cache
    '--windowed',  # Windows only: hide the console
    f'--workpath={os.path.join(script_dir, "build")}',  # build files location
    f'--distpath={os.path.join(script_dir, "dist")}',  # exe output location
])