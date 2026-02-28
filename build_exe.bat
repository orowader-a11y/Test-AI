@echo off
setlocal

if not exist venv (
  py -3 -m venv venv
)
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pyinstaller --noconfirm --windowed --onefile --name FrontendZipSecurityAnalyzer app.py

echo Build finished. EXE is in dist\FrontendZipSecurityAnalyzer.exe
