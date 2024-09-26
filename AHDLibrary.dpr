library AHDLibrary;

// AndHill Development Runtime Library
// Programmiert und entwickelt von Andreas Hiller
// Copyright © 2020 AndHill Development
// Alle Rechte vorbehalten

// Diese Bibliothek enthält eine Sammlung von Funktionen die in meinen Programmen immer
// wieder benutzt werden. Diese Bibliothek kann nur mit Delphiprogrammen benutzt werden
// da hier Strings exportiert werden und dafür der Borland Speichermanager benötigt wird.
  

uses
  ShareMem,
  Windows,
  SysUtils,
  Forms,
  Dialogs,
  Classes,
  Registry,
  MMSystem,
  TlHelp32,
  AdvStyleIF,
  AdvAppStyler,
  IniFiles,
  FileCtrl,
  Controls,
  StdCtrls,
  Graphics,
  ShellAPI,
  JPEG,
  PngImage,
  Math,
  IdBaseComponent,
  IdComponent,
  IdTCPConnection,
  IdTCPClient,
  IdHTTP,
  WinInet,
  StrUtils;

type
  //http://msdn2.microsoft.com/en-us/library/ms724833.aspx
  TOSVersionInfoEx = packed record
    dwOSVersionInfoSize : DWORD;
    dwMajorVersion      : DWORD;
    dwMinorVersion      : DWORD;
    dwBuildNumber       : DWORD;
    dwPlatformId        : DWORD;
    szCSDVersion        : array[0..127] of Char;
    wServicePackMajor   : WORD;
    wServicePackMinor   : WORD;
    wSuiteMask          : WORD;
    wProductType        : BYTE;
    wReserved           : BYTE;
  end;

const
  VER_SUITE_PERSONAL  = $00000200;
  VER_NT_WORKSTATION  = $00000001;
  VER_SUITE_WH_SERVER = $00008000;
  SM_SERVERR2         = 89;

type
  TStrArray = array of string;

type
  TArithRoundToRange = -37..37;

function GetOSVersionEx(var lpVersionInformation: TOSVersionInfoEx): BOOL; stdcall; external kernel32 name 'GetVersionExA';  

{$R *.res}

// -- Systemfunktionen --------------------------------------------------------------------

// Überprüfen ob man Admin ist
function IsAdmin: Boolean; StdCall;
const
  SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority =
  (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_BUILTIN_DOMAIN_RID = $00000020;
  DOMAIN_ALIAS_RID_ADMINS     = $00000220;

var
  hAccessToken: THandle;
  ptgGroups: PTokenGroups;
  dwInfoBufferSize: DWORD;
  psidAdministrators: PSID;
  x: Integer;
  bSuccess: BOOL;
begin
  Result := False;
  bSuccess:=False;
  ptgGroups:=nil;
  psidAdministrators:=nil;
  try
    bSuccess := OpenThreadToken(GetCurrentThread, TOKEN_QUERY, True,
      hAccessToken);
    if not bSuccess then
    begin
      if GetLastError = ERROR_NO_TOKEN then
      bSuccess := OpenProcessToken(GetCurrentProcess, TOKEN_QUERY,
        hAccessToken);
    end;
    if bSuccess then
    begin
      GetMem(ptgGroups, 1024);
      bSuccess := GetTokenInformation(hAccessToken, TokenGroups,
        ptgGroups, 1024, dwInfoBufferSize);
      if bSuccess then
      begin
        AllocateAndInitializeSid(SECURITY_NT_AUTHORITY, 2,
          SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
          0, 0, 0, 0, 0, 0, psidAdministrators);
        {$R-}
        for x := 0 to ptgGroups.GroupCount - 1 do
          if EqualSid(psidAdministrators, ptgGroups.Groups[x].Sid) then
          begin
            Result := True;
            Break;
          end;
        {$R+}
      end;
    end;
  finally
    if bSuccess then
      CloseHandle(hAccessToken);
    if Assigned(ptgGroups) then
      FreeMem(ptgGroups);
    if Assigned(psidAdministrators) then
      FreeSid(psidAdministrators);
  end;
end;

// Benutzername ermitteln
function GetUsername: String; StdCall;
var
  Buffer: array[0..255] of Char;
  Size: DWord;
begin
  Size := SizeOf(Buffer);
  if not Windows.GetUserName(Buffer, Size) then
    RaiseLastOSError; //RaiseLastWin32Error; {Bis D5};
  SetString(Result, Buffer, Size - 1);
end;

// Aktuelles Hardwareprofil ermitteln
function GetHardwareProfileName: String; StdCall;
var
  HwPi: THWProfileInfo;
begin
  GetCurrentHwProfile(HwPi);
  Result := HwPi.szHwProfileName;
end;

// Anzahl der Prozessoren ermitteln
function GetNumberOfProcessors: Integer; StdCall;
var
  SystemInfo: TSystemInfo;
begin
  GetSystemInfo(SystemInfo);
  Result:=SystemInfo.dwNumberOfProcessors;
end;

// BIOS-Datum ermitteln
function GetBiosDate: String; StdCall;
  function SegOfsToLinear(Segment, Offset: Word): Integer;
  begin
    result := (Segment shl 4) or Offset;
  end;
begin
  result := string(PChar(Ptr(SegOfsToLinear($F000, $FFF5))));
end;

// Überprüfen ob eine Maus verfügbar ist
function MouseExists: Boolean; StdCall;
begin
  Result:= GetSystemMetrics(SM_MOUSEPRESENT) <> 0 
end;

function GetMemInfo(flag: Integer): Integer; StdCall;
var
  Memory: TMemoryStatus;
begin
  Memory.dwLength := SizeOf(Memory);
  GlobalMemoryStatus(Memory);
  case flag of
    1: result:=Memory.dwTotalPhys div 1024;     // physischer Speicher
    2: result:=Memory.dwAvailPhys div 1024;     // verfügbarer physischer Speicher
    3: result:=Memory.dwTotalVirtual div 1024;  // virtueller Speicher
    4: result:=Memory.dwAvailVirtual div 1024;  // verfügbarer virtueller Speicher
    5: result:=Memory.dwTotalPageFile div 1024; // Auslagerungsspeicher
    6: result:=Memory.dwAvailPageFile div 1024; // verfügbarer Auslagerungsspeicher
  end;
end;

// Speicher des angegebenen Datenträgers ermitteln
function GetDiskSpaceEx(drive: String; flag: Integer): Integer; StdCall;
var freeCaller, total: Int64;
begin
  GetDiskFreeSpaceEx(PChar(drive), freeCaller, total, nil);
  case flag of
    1: result:=freeCaller;  // freier Speicher
    2: result:=total;       // gesamter Speicher
  end;
end;

// Name des Prozessors ermitteln
function GetProzessorName: String; StdCall;
var reg: TRegistry;
begin
  result:='No ascertainable. Admin rights needed';
  reg:=TRegistry.Create;
  try
    reg.RootKey := HKEY_LOCAL_MACHINE;
    reg.OpenKey('Hardware\Description\System\CentralProcessor\0', false);
	if reg.ReadString('ProcessorNameString') = '' then
		result:='No ascertainable. Admin rights needed'
	else
		result:=reg.ReadString('ProcessorNameString');
  finally
    reg.free;
  end;
end;

// Überprüfen ob die CPU MMX unterstützt
function IsMMX: Boolean; StdCall;
asm
  PUSH    EBX
  PUSHFD                       // Erweiterte Flags holen
  POP     EAX                  // In EAX speichern
  MOV     ECX, EAX             // In ECX speichern
  XOR     EAX, $00200000       // Bit 21 negieren
  PUSH    EAX
  POPFD
  PUSHFD                       // Erweiterte Flags holen
  POP     EAX                  // In EAX speichern
  XOR     EAX, ECX             // Wenn sich BIT 21 schreiben
  JE      @@NoMMX              // Der Befehl CPUID wird
  MOV     EAX, $01             // Feature Flags anfragen
  DB      $0F,$A2              // $0F, $A2 CPUID Befehl
  XOR     EAX, EAX
  TEST    EDX, $800000         // MMX ist vorhanden wenn Bit 23 gesetzt ist
  JZ      @@NoMMX
  MOV     EAX, 1               // True
@@NoMMX:
  POP     EBX
end;

// Taktfrequenz ermitteln
function CalcCPUSpeed: Extended; StdCall;
const
  DelayTime = 500; // measure time in ms
var
  TimerHi, TimerLo: DWord;
  PriorityClass, Priority: Integer;
begin
  try
    PriorityClass := GetPriorityClass(GetCurrentProcess);
    Priority := GetThreadPriority(GetCurrentThread);

    SetPriorityClass(GetCurrentProcess, REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread,
                      THREAD_PRIORITY_TIME_CRITICAL);
    try
      Sleep(10);
      asm
        dw 310Fh // rdtsc
        mov TimerLo, eax
        mov TimerHi, edx
      end;
      Sleep(DelayTime);
      asm
        dw 310Fh // rdtsc
        sub eax, TimerLo
        sbb edx, TimerHi
        mov TimerLo, eax
        mov TimerHi, edx
      end;
    finally
      SetThreadPriority(GetCurrentThread, Priority);
      SetPriorityClass(GetCurrentProcess, PriorityClass);
    end;
    Result := TimerLo / (1000.0 * DelayTime);
  except
    Result := 0;
  end;
end;

// Überprüfen ob eine Soundkarte installiert ist
function IsSoundCard: Boolean; StdCall;
begin
  Result:=WaveOutGetNumDevs > 0;
end;

// Anwendung für eine bestimmte Zeit pausieren
procedure SetDelay(const Milliseconds: DWord); StdCall;
var
  FirstTickCount: DWord;
begin
  FirstTickCount := GetTickCount;
  while ((GetTickCount - FirstTickCount) < Milliseconds) do
  begin
    Application.ProcessMessages;
    Sleep(0);
  end;
end;

// Überprüfen ob eine Exe-Datei ausgeführt wird
function IsExeRunning(const AExeName: String): Boolean; StdCall;
var
  h: THandle;
  p: TProcessEntry32;
begin
  Result := False;

  p.dwSize := SizeOf(p);
  h := CreateToolHelp32Snapshot(TH32CS_SnapProcess, 0);
  try
    Process32First(h, p);
    repeat
      Result := AnsiUpperCase(AExeName) = AnsiUpperCase(p.szExeFile);
    until Result or (not Process32Next(h, p));
  finally
    CloseHandle(h);
  end;
end;

// String aus der Registry lesen
function ReadFromRegistry(Section, Key: String; RootKey: HKEY): String; StdCall;
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  try
    Reg.RootKey:=RootKey;
    Reg.OpenKey(Section, true);
    result:=Reg.ReadString(Key);
  finally
    Reg.Free;
  end;
end;

// String in die Registry schreiben
Procedure WriteToRegistry(Section, Key, Value: String; RootKey: HKEY); StdCall;
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  try
    Reg.RootKey:=RootKey;
    Reg.OpenKey(Section, true);
    Reg.WriteString(Key, Value);
  finally
    Reg.Free;
  end;
end;

// Windowsversion ermitteln (Interne Hilfsfunktion
function GetOSVersionInfoEx : TOSVersionInfoEx;
var
  OSVersionInfo   : TOSVersionInfo absolute Result;
  Done : Boolean;
begin
  FillChar(Result, SizeOf(Result), #0);
  Done := False;
  try
    Result.dwOSVersionInfoSize := SizeOf(TOSVersionInfoEx);
    Done := GetOSVersionEx(Result);
  except
  end;
  if not(Done) then
  begin
    try
      FillChar(Result, SizeOf(Result), #0);
      Result.dwOSVersionInfoSize := SizeOf(TOSVersionInfo);
      Done := GetVersionEx(OSVersionInfo);
    except
    end;
  end;
end;

// Windowsversion ermitteln
function GetWinVersion: String; StdCall;
var
  OSInfo : TOSVersionInfoEx;
begin
  Result := 'Unbekannte Windows-Version';
  OSInfo := GetOSVersionInfoEx;
  case OSInfo.dwPlatformId of
    VER_PLATFORM_WIN32s:
    begin
      Result := 'Win32s';
    end;
    VER_PLATFORM_WIN32_WINDOWS:
    begin
      if (OSInfo.dwMajorVersion = 4) and (OSInfo.dwMinorVersion =  0) then
        Result := 'Windows 95';
      if (OSInfo.dwMajorVersion = 4) and (OSInfo.dwMinorVersion = 10) then
        Result := 'Windows 98';
      if (OSInfo.dwMajorVersion = 4) and (OSInfo.dwMinorVersion = 90) then
        Result := 'Windows Millennium Edition';
    end;
    VER_PLATFORM_WIN32_NT:
    begin
      if (OSInfo.dwMajorVersion = 4) and (OSInfo.dwMinorVersion = 0) then
        Result := 'Windows NT';
      if (OSInfo.dwMajorVersion = 5) and (OSInfo.dwMinorVersion = 0) then
        Result := 'Windows 2000';
      if (OSInfo.dwMajorVersion = 5) and (OSInfo.dwMinorVersion = 1) then
        Result := 'Windows XP';

      if (OSInfo.dwMajorVersion = 5) and (OSInfo.dwMinorVersion = 2) then
      begin
        if GetSystemMetrics(SM_SERVERR2) <> 0 then
          Result := 'Windows Server 2003 "R2"'
         else
           if (OSInfo.wProductType = VER_NT_WORKSTATION) then
             Result := 'Windows XP x64'
           else
             if OSInfo.wSuiteMask = VER_SUITE_WH_SERVER then
               Result := 'Windows Home Server'
             else
               Result := 'Windows Server 2003';
      end;
      if (OSInfo.dwMajorVersion = 6) and (OSInfo.dwMinorVersion = 0) then
      begin
        if (OSInfo.wProductType = VER_NT_WORKSTATION) then
          Result := 'Windows Vista'
        else
          Result := 'Windows Server 2008';
      end;
      if (OSInfo.dwMajorVersion = 6) and (OSInfo.dwMinorVersion = 1) then
      begin
        if (OSInfo.wProductType = VER_NT_WORKSTATION) then
          Result := 'Windows 7'
        else
          Result := 'Windows Server 2008 R2';
      end;
      if (OSInfo.wSuiteMask and VER_SUITE_PERSONAL) = VER_SUITE_PERSONAL then
        Result := Result + ' Home Edition'
      else
        Result := Result + ' Professional';
    end;
  end;
  Result := Trim(Result + ' ' + OSInfo.szCSDVersion);
end;

// Auflösung ermitteln
function GetScreenRes(flag:Integer): Integer; StdCall;
begin
  case flag of
    1: result:=Screen.Width;
    2: result:=Screen.Height;
  end;
end;

// Farbtiefe ermitteln
function ScreenBitsPerPixel: Integer; StdCall;
var
  DC: HDC;
begin
  DC := GetDC(0);  // Device-Context des Desktops
  try
    Result := GetDeviceCaps(DC, BITSPIXEL);
  finally
    ReleaseDC(0, DC);
  end;
end;

// Bootmodus ermitteln
function GetBootModus: String; StdCall;
begin
  case GetSystemMetrics(SM_CLEANBOOT) of
    0: result:='Normaler Modus';
    1: result:='Abgesicherter Modus';
    2: result:='Abgesicherter Modus (Netzwerk)';
  end;
end;

// Umgebungsvariable auslesen
function GetEnvVar(variable: String): String; StdCall;
begin
  result:=GetEnvironmentVariable(variable);
end;

// Zeitzone ermitteln
function GetTimeZone: String; StdCall;
var T: TIME_ZONE_INFORMATION;
begin
  case GetTimeZoneInformation(T) of
    TIME_ZONE_ID_UNKNOWN: Result := 'unbekannt';
    TIME_ZONE_ID_STANDARD: Result := T.StandardName;
    TIME_ZONE_ID_DAYLIGHT: Result := T.DayLightName;
  end;
end;

// Strings zerstückeln (interne Hilfsfunktion)
function Explode(var a: TStrArray; Border, S: String): Integer;
var
  S2: string;
begin
  Result  := 0;
  S2 := S + Border;
  repeat
    SetLength(A, Length(A) + 1);
    a[Result] := Copy(S2, 0,Pos(Border, S2) - 1);
    Delete(S2, 1,Length(a[Result] + Border));
    Inc(Result);
  until S2 = '';
end;

// Programmtitel erstellen
function GetProgramTitle(name, version: String): String; StdCall;
var
  A: TStrArray;
  output: string;
begin
  Explode(A, '.', version);
  output:=name+' V'+A[0]+'.'+A[1]+'.'+A[2]+' Build '+A[3];
  result:=output;
end;

// Get Version Parts
function GetVersionPart(fileversion: String; flag: Integer): Integer;
var
  A: TStrArray;
begin
  Explode(A, '.', fileversion);
  result:=StrToInt(A[flag]);
end;

// Versionsüberprüfung
function IsVersionNewer(oldversion, newversion: String): Boolean; StdCall;
var
  A,B: TStrArray;
  oldbuild, newbuild: integer;
begin
  Explode(A, '.', oldversion);
  Explode(B, '.', newversion);
  oldbuild:=StrToInt(A[3]);
  newbuild:=StrToInt(B[3]);
  if newbuild > oldbuild then
  begin
    result:=true;
  end
  else
  begin
    result:=false;
  end;
end;

function SetStyle(Flag: Integer): TTMSStyle; StdCall;
begin
  case Flag of
    0: result:=tsOffice2003Blue;
    1: result:=tsOffice2003Classic;
    2: result:=tsOffice2003Olive;
    3: result:=tsOffice2003Silver;
    4: result:=tsOffice2007Luna;
    5: result:=tsOffice2007Obsidian;
    6: result:=tsOffice2007Silver;
    7: result:=tsOffice2010Black;
    8: result:=tsOffice2010Blue;
    9: result:=tsOffice2010Silver;
    10: result:=tsTerminal;
    11: result:=tsWhidbey;
    12: result:=tsWindowsXP;
    13: result:=tsWindowsVista;
    14: result:=tsWindows7;
  end;
end;

function IsWindows64: Boolean; StdCall;
type 
  TIsWow64Process = function( // Type of IsWow64Process API fn 
    Handle: Windows.THandle; var Res: Windows.BOOL 
  ): Windows.BOOL; stdcall; 
var 
  IsWow64Result: Windows.BOOL; // Result from IsWow64Process 
  IsWow64Process: TIsWow64Process; // IsWow64Process fn reference 
begin 
  // Try to load required function from kernel32 
  IsWow64Process := Windows.GetProcAddress( 
    Windows.GetModuleHandle('kernel32'), 'IsWow64Process' 
  ); 
  if Assigned(IsWow64Process) then 
  begin 
    // Function is implemented: call it 
    if not IsWow64Process( 
      Windows.GetCurrentProcess, IsWow64Result 
    ) then 
      raise SysUtils.Exception.Create('IsWindows64: bad process handle'); 
    // Return result of function 
    Result := IsWow64Result; 
  end 
  else 
    // Function not implemented: can't be running on Wow64 
    Result := False; 
end;

// -- Dateifunktionen ---------------------------------------------------------------------

// Datei zur Anzeige kürzen
function GetShortPath(Path: String; Canvas: TCanvas; Len: Integer): String; StdCall;
begin
  Result:=MinimizeName(Path,Canvas,Len);
end;

// Ini-Datei lesen
function ReadFromIni(Filename, Section, Key: String): String; StdCall;
var
  ini: TIniFile;
begin
  ini:=TIniFile.Create(Filename);
  try
    result:=ini.ReadString(Section, Key, '');
  finally
    ini.Free;
  end;
end;

// Ini-Datei schreiben
procedure WriteToIni(Filename, Section, Key, Value: String); StdCall;
var
  ini: TIniFile;
begin
  ini:=TIniFile.Create(Filename);
  try
    ini.WriteString(Section, Key, Value);
  finally
    ini.Free;
  end;
end;

// Dateityp-Beschreibung ermitteln
function GetFileTypeName(const Filename: String): String; StdCall;
  var Info: TSHFileInfo;
begin
  if SHGetFileInfo(PChar(Filename), 0, Info, SizeOf(Info), SHGFI_TYPENAME) = 0 then
    Result := Info.szTypeName
  else
    Result := '';
end;

// Dateiversion einer EXE oder DLL auslesen
function GetFileVersion(Path: String): String; StdCall;
var
  lpVerInfo: pointer;
  rVerValue: PVSFixedFileInfo;
  dwInfoSize: cardinal;
  dwValueSize: cardinal;
  dwDummy: cardinal;
  lpstrPath: pchar;

begin
  if Trim(Path) = EmptyStr then
    lpstrPath := pchar(ParamStr(0))
  else
    lpstrPath := pchar(Path);

  dwInfoSize := GetFileVersionInfoSize(lpstrPath, dwDummy);

  if dwInfoSize = 0 then
  begin
    Result := '0.0.0.0';
    Exit;
  end;

  GetMem(lpVerInfo, dwInfoSize);
  GetFileVersionInfo(lpstrPath, 0, dwInfoSize, lpVerInfo);
  VerQueryValue(lpVerInfo, '\', pointer(rVerValue), dwValueSize);

  with rVerValue^ do
  begin
    Result := IntTostr(dwFileVersionMS shr 16);
    Result := Result + '.' + IntTostr(dwFileVersionMS and $FFFF);
    Result := Result + '.' + IntTostr(dwFileVersionLS shr 16);
    Result := Result + '.' + IntTostr(dwFileVersionLS and $FFFF);
  end;
  FreeMem(lpVerInfo, dwInfoSize);
end;

// Größe einer Datei ermitteln
function GetFileSizeEx(const AFileName: String): Int64; StdCall;
var
  F: TSearchRec;
begin
  Result := -1;
  if FindFirst(AFileName, faAnyFile, F) = 0 then
  begin
    try
      Result :=  F.FindData.nFileSizeLow or (F.FindData.nFileSizeHigh shl 32);
    finally
      SysUtils.FindClose(F);
    end;
  end;
end;

// Systemverzeichnis ermitteln
function GetSystemDir: String; StdCall;
var
  Dir: string;
  Len: DWord;
begin
  SetLength(Dir,MAX_PATH);
  Len:=GetSystemDirectory(PChar(Dir),MAX_PATH);
  if Len>0 then
  begin
    SetLength(Dir,Len);
    Result:=Dir;
  end
  else
    RaiseLastOSError;
end;

// Windowsverzeichnis ermitteln
function GetWinDir: String; StdCall;
var
  Dir: string;
  Len: DWord;
begin
  SetLength(Dir,MAX_PATH);
  Len:=GetWindowsDirectory(PChar(Dir),MAX_PATH);
  if Len>0 then
  begin
    SetLength(Dir,Len);
    Result:=Dir;
  end
  else
    RaiseLastOSError;
end;

// Temporäres Verzeichnis ermitteln
function GetTempDir: String;
begin
  result := SysUtils.GetEnvironmentVariable('temp');
end;

// Dateien und Verzeichnisse rekursiv Löschen
function DeleteFiles(const AFile: String): Boolean; StdCall;
var
  sh: SHFileOpStruct;
begin
  ZeroMemory(@sh, SizeOf(sh));
  with sh do
  begin
    Wnd := Application.Handle;
    wFunc := FO_DELETE;
    pFrom := PChar(AFile +#0);
    fFlags := FOF_SILENT or FOF_NOCONFIRMATION;
  end;
  result := SHFileOperation(sh) = 0;
end;

// Dateien ausführen
procedure ExecuteFile(Filename, Params, WorkDir: String); StdCall;
begin
  ShellExecute(Application.Handle, 'open', PChar(Filename), PChar(Params), PChar(WorkDir), SW_NORMAL)
end;

procedure FindAllFiles(const FileList: tstrings;RootFolder: string; Maske: array of string; Recurse: Boolean = True); Stdcall;
var
  SR: TSearchRec;
  i : integer;
  filename: String;
begin
  RootFolder := IncludeTrailingPathDelimiter(RootFolder);

  if Recurse then
    if FindFirst(RootFolder + '*.*', faAnyFile, SR) = 0 then
    try
      repeat
        if SR.Attr and faDirectory = faDirectory then
            // --> ein Verzeichnis wurde gefunden
            // der Verzeichnisname steht in SR.Name
            // der vollständige Verzeichnisname (inkl. darüberliegender Pfade) ist
            // RootFolder + SR.Name
          if (SR.Name <> '.') and (SR.Name <> '..') then

          //filename:=StringReplace(SR.Name,ExtractFileExt(SR.Name),'',[rfReplaceAll,rfIgnoreCase]);

            FindAllFiles(FileList, SR.Name, Maske, Recurse);
      until FindNext(SR) <> 0;
    finally
      FindClose(SR);
    end;
  i := 0;
  repeat
    begin
      if FindFirst(RootFolder + '*' + Maske[i], faAnyFile, SR) = 0 then
      try
        repeat
          if SR.Attr and faDirectory <> faDirectory then
          begin
            FileList.Add(SR.Name);
          end;
        until FindNext(SR) <> 0;
      finally
        FindClose(SR);
      end;
      i := i + 1;
    end
  until
    i = high(maske) + 1;
end;

// -- Netzwerkfunktionen ------------------------------------------------------------------

// Datei per HTTP Downloaden
procedure DownloadFile(Source, Destination: String; Client: TidHttp); Stdcall;
var
  lStream: TFileStream;
begin
  lStream:=TFileStream.Create(Destination, fmCreate or fmShareDenyWrite);
  try
     client.Get(Source,lStream);
  finally
    lStream.Free;
  end;
end;

// Computername Ermitteln
function GetComputerName: String; StdCall;
var
  Len: DWORD;
begin
  Len:=MAX_COMPUTERNAME_LENGTH+1;
  SetLength(Result,Len);
  if Windows.GetComputerName(PChar(Result), Len) then
    SetLength(Result,Len)
  else
    RaiseLastOSError;
end;

function KillTask(ExeFileName: String): Integer; Stdcall;
const
  PROCESS_TERMINATE = $0001;
var
  ContinueLoop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
begin
  Result := 0;
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);

  while Integer(ContinueLoop) <> 0 do
  begin
    if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) =
      UpperCase(ExeFileName)) or (UpperCase(FProcessEntry32.szExeFile) =
      UpperCase(ExeFileName))) then
      Result := Integer(TerminateProcess(
                        OpenProcess(PROCESS_TERMINATE,
                                    BOOL(0),
                                    FProcessEntry32.th32ProcessID),
                                    0));
     ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);
  end;
  CloseHandle(FSnapshotHandle);
end;

// -- Mathematikfunktionen ----------------------------------------------------------------

// Arithmetisch Runden
function ArithRound(Value: Extended): Int64; StdCall;
var
  TmpSign : TValueSign;
begin
  TmpSign  := Sign(Value);
  if TmpSign = ZeroValue then
    Result := 0
  else
    Result := Trunc(Abs(Value) + 0.5) * TmpSign;
end;

// Arithmetisch Runden (Fließkommazahlen)
function ArithRoundTo(Value: Extended; Digit : TArithRoundToRange): Extended; StdCall;
const
  Resolution : Extended = 1E-19 * 1000;
  Adjustment : Extended = 0.5;
var
  Factor  : Extended;
  TmpSign : TValueSign;
  Mode    : TFPURoundingMode;
begin
  TmpSign  := Sign(Value);
  if TmpSign = ZeroValue then
    Result := 0
  else
  begin
    Factor := IntPower(10, Digit);
    Mode   := GetRoundMode;
    SetRoundMode(rmUp);
    try
      Result := Int((Abs(Value) + Resolution) / Factor + Adjustment) *
                Factor * TmpSign;
    finally
      SetRoundMode(Mode);
    end;
  end;
end;

// Beliebig Potenzionieren
Function Potenz(Base, Exponent: Extended): Extended; StdCall;
begin
  if Exponent = 0.0 then
    Result := 1.0
  else if (Base = 0.0) and (Exponent > 0.0) then
    Result := 0.0
  else if Exponent = 2 then
    result := Sqr(Base)
  else
    Result := Exp(Ln(Base) * Exponent );
end;

// Primzahlen erkennen
function IsPrime(ANumber: Cardinal): Boolean; StdCall;
var
  DivCount: Integer;
  Divisor: Cardinal;
begin
  DivCount := 0;
  if (ANumber > 0) then
  begin
    for Divisor := 1 to ANumber do
    begin
      if (ANumber mod Divisor) = 0 then
        Inc(DivCount);
      if (DivCount > 2) then
        Break;
    end;
  end;
  Result := (DivCount = 2);
end;

// Quersumme errechnen
function DigitSum(i : Integer): Integer; StdCall;
var
  p: PChar;
begin
  Result := 0;
  p := PChar(IntToStr(i));
  while (p^ <> #0) do
  begin
    Result := Result + StrToInt(p^);
    Inc(p);
  end;
end;

// n-te Wurzel bereichnen
function NteWurzel(n, radikand: Integer): Real; StdCall;
begin
  if radikand>=0 then
    result:=power(radikand, 1/n)
  else result:=-1;
end;

// Sinus
function Sinus(angle: Real): Real; StdCall;
begin
  result := sin(Pi*angle/180);
end;

// Cosinus
function Cosinus(angle: Real): Real; StdCall;
begin
  result := cos(Pi*angle/180);
end;

// Sekunden in Stunden, Minuten und Sekunden umwandeln
function GetTimeString(seconds: Integer): String; StdCall;
var
  Tage, Stunden, Minuten, Sekunden, Teiler, SekundenEin: Integer;
  Stunden1, Minuten1, Sekunden1: String;
begin
  SekundenEin := seconds;
  Teiler := 60;
  Sekunden := SekundenEin mod Teiler;
  Minuten  := (SekundenEin div Teiler) mod Teiler;
  Stunden  := (SekundenEin div Teiler) div Teiler;

  if Sekunden < 10 then
    Sekunden1:='0'+IntToStr(Sekunden)
  else
    Sekunden1:=IntToStr(Sekunden);

  if Minuten < 10 then
    Minuten1:='0'+IntToStr(Minuten)
  else
    Minuten1:=IntToStr(Minuten);

  if Stunden < 10 then
    Stunden1:='0'+IntToStr(Stunden)
  else
    Stunden1:=IntToStr(Stunden);

  result:=Stunden1+':'+Minuten1+':'+Sekunden1;
end;

function RundeAufStelle(zahl: Double; stellen: Integer): Double; StdCall;
var multi: double;
begin
  multi:=IntPower(10, stellen);
  zahl:=round(zahl*multi);
  result:=zahl/multi;
end;

// -- Grafikfunktionen --------------------------------------------------------------------

// Bitmap in JPEG umwandeln
procedure ConvertBMPToJPG(const Filename: String; Quality: TJPEGQualityRange=100); StdCall;
var
  Bmp: TBitmap;
  Jpg: TJpegImage;
begin
  Bmp := TBitmap.Create;
  Jpg := TJpegImage.Create;
  try
    Bmp.LoadFromFile(Filename);
    Jpg.CompressionQuality:=Quality;
    Jpg.Assign(Bmp);
    Jpg.SaveToFile(ChangeFileExt(Filename, '.jpg' ));
  finally
    Jpg.Free;
    Bmp.Free;
  end;
end;

// JPEG in Bitmap umwandeln
procedure ConvertJPGToBMP(const Filename: String); StdCall;
var
jpeg: TJPEGImage;
bmp: TBitmap;
begin
jpeg:=TJPEGImage.Create;
try
   jpeg.LoadFromFile(Filename);
   bmp:=TBitmap.Create;
   try
     bmp.Assign(jpeg);
     bmp.SaveToFile(ChangeFileExt(Filename, '.bmp'));
   finally
     bmp.free;
   end;
finally
   jpeg.free;
end;
end;

procedure ConvertPngToJPG(input, output: String); StdCall;
var
  oBitmap :TBitmap;
  oJPG :TJPEGImage;
  oPNG :TPNGObject;
begin
  oPNG := TPNGObject.Create;
  oPNG.LoadFromFile(input);
  oBitmap := TBitmap.Create;
  oBitmap.Assign(oPNG);
  FreeAndNil(oPNG);
  oJPG := TJPEGImage.Create;
  oJPG.CompressionQuality := 100;
  oJPG.Assign(oBitmap);
  FreeAndNil(oBitmap);
  oJPG.SaveToFile(output);
  FreeAndNil(oJPG);
end;

procedure ConvertJPGToPNG(input, output: String); StdCall;
var
  oBitmap :TBitmap;
  oJPG :TJPEGImage;
  oPNG :TPNGObject;
begin
  oJPG := TJPEGImage.Create;
  oJPG.CompressionQuality:=100;
  oJPG.LoadFromFile(input);
  oBitmap := TBitmap.Create;
  oBitmap.Assign(oJPG);
  FreeAndNil(oJPG);
  oPNG := TPNGObject.Create;
  oPNG.Assign(oBitmap);
  FreeAndNil(oBitmap);
  oPNG.SaveToFile(output);
  FreeAndNil(oPNG);
end;

// -- Dialoge -----------------------------------------------------------------------------

// -- Sonstiges ---------------------------------------------------------------------------

function CreateUUID: String; Stdcall;
var
  uuid: TGUID;
  uuidStr: String;
begin
  CreateGUID(uuid);
  uuidStr:=GUIDToString(uuid);
  uuidStr:=StringReplace(uuidStr, '{', '', [rfReplaceAll]);
  uuidStr:=StringReplace(uuidStr, '}', '', [rfReplaceAll]);
  result:=LowerCase(uuidStr);
end;

Exports

IsAdmin,
GetUsername,
GetHardwareProfileName,
GetNumberOfProcessors,
GetBiosDate,
MouseExists,
GetMemInfo,
GetDiskSpaceEx,
GetProzessorName,
IsMMX,
CalcCPUSpeed,
IsSoundcard,
SetDelay,
IsExeRunning,
ReadFromRegistry,
WriteToRegistry,
GetWinVersion,
GetScreenRes,
ScreenBitsPerPixel,
GetBootModus,
GetEnvVar,
GetTimeZone,
GetProgramTitle,
GetVersionPart,
IsVersionNewer,
SetStyle,
IsWindows64,
GetShortPath,
ReadFromIni,
WriteToIni,
GetFileTypeName,
GetFileVersion,
GetFileSizeEx,
GetSystemDir,
GetWinDir,
GetTempDir,
DeleteFiles,
ExecuteFile,
KillTask,
ConvertBMPToJPG,
ConvertJPGToBMP,
ConvertPngToJPG,
ConvertJPGToPNG,
ArithRound,
ArithRoundTo,
Potenz,
IsPrime,
DigitSum,
NteWurzel,
Sinus,
Cosinus,
GetTimeString,
DownloadFile,
GetComputerName,
RundeAufStelle,
CreateUUID,
FindAllFiles;

begin
end.

 