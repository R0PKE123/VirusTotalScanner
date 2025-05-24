# What is this project?
This project is an apllication that automaticaly scans the download directory for viruses and shows a warning box if there is a virus detected by virus total and gives an option of deleting it
# How to use it
## Installing
Download the installer exe from the releases section and running it
## Features
A web interface at http://localhost:8080/, automatic startup, uninstaller.
## How to build it from source
Download and install node, angular console and inno setup (if you don't have it already)\
Download [The frontend](https://github.com/R0PKE123/VirusTotalScannerFrontend) then open up a terminal and navigate to the frontend directory \
Run npm install and then npm run build --prod\
Download this repo\
Copy the contens of the browser folder inside of dist and VirusTotalScannerFrontend folders to this repo's src/main/resources/static folder \
Run ./mvnw clean package -DskipTests in console \
open the Setup.iss file and click Ctrl + f9 to compile open the .exe in Output folder
## How to uninstall
Go to setting apps search for Virus Total Scanner click the threee dots and click uninstall
