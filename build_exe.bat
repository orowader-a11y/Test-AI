@echo off
setlocal

if not exist venv (
  py -3 -m venv venv
)
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
REM requirements.txt includes python-sonarqube-api for optional SonarQube server integration (config: sonar.url, sonar.projectKey, SONAR_TOKEN)
pyinstaller --noconfirm --windowed --onefile --name FrontendZipSecurityAnalyzer app.py

echo Build finished. EXE is in dist\FrontendZipSecurityAnalyzer.exe
