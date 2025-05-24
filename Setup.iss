[Setup]
AppName=Virus Total Scanner
AppVersion=1.0
DefaultDirName={commonpf}\VirusTotalScanner
DefaultGroupName=VirusTotalScanner
OutputBaseFilename=Virus Total Scanner Installer
Compression=lzma
SolidCompression=yes

[Files]
Source: "CreateShortcut.vbs"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "target/app.jar"; DestDir: "{app}"; Flags: ignoreversion
Source: "jdk-17.0.12_windows-x64_bin.msi"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{tmp}\CreateShortcut.vbs"" ""{userstartup}\VirusTotalScanner.lnk"" ""java"" ""-jar"" ""app.jar"" ""{app}"""; Flags: runhidden
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\jdk-17.0.12_windows-x64_bin.msi"" /qn"; \
  Flags: runhidden waituntilterminated; \
  Check: not IsJavaInstalled()

[Code]
function IsJavaInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  // Run 'java -version' to check if Java is on PATH
  if Exec('java', '-version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := (ResultCode = 0);
  end else
    Result := False;
end;

procedure InitializeWizard();
begin
  if not IsJavaInstalled() then
  begin
    MsgBox('Java is required and will be installed.', mbInformation, MB_OK);
  end;
end;