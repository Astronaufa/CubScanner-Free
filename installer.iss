#define MyAppName        "CubScanner Free"
#define MyAppVersion     "12.0"
#define MyAppPublisher   "CubScanner Project"
#define MyAppURL         "https://ko-fi.com/pietro67"
#define MyAppExeName     "CubScannerFree.exe"

[Setup]
AppId={{8F4B5C2A-9D3E-4E1F-A8C7-2B6D5E4F3A91}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\CubScannerFree
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=LICENSE.txt
OutputDir=dist
OutputBaseFilename=CubScannerFree_Setup
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
SetupLogging=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
MinVersion=10.0

; --- CAPA DO INSTALADOR ---
WizardImageFile=logo.png
WizardSmallImageFile=logo.png
; ---------------------------

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "portuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
Source: "dist\CubScannerFree.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "logo.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

#if FileExists(AddBackslash(SourcePath) + "npcap-1.79.exe")
Source: "npcap-1.79.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
#define NPCAP_BUNDLED
#endif

#if FileExists(AddBackslash(SourcePath) + "README_FREE.md")
Source: "README_FREE.md"; DestDir: "{app}"; DestName: "README.md"; Flags: ignoreversion isreadme
#endif
#if FileExists(AddBackslash(SourcePath) + "LICENSE.txt")
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
#endif

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\icon.ico"

[Run]
#ifdef NPCAP_BUNDLED
Filename: "{tmp}\npcap-1.79.exe"; \
    Parameters: "/S /winpcap_mode=enforced /loopback_support=yes"; \
    StatusMsg: "Installing Npcap..."; \
    Flags: waituntilterminated; \
    Check: not IsNpcapInstalled
#endif
Filename: "{app}\{#MyAppExeName}"; \
    Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\.cubscanner"

[Code]
function IsNpcapInstalled(): Boolean;
begin
  Result :=
    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst')
    or RegKeyExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst');
end;