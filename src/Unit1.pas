unit Unit1;

{
  PortScanner v1.0
  Author: Sergej N.

  Multithreaded TCP port scanner for Windows.
  Full port range scanning 1-65535.
  Detects open ports and measures response time.
  Supports export to HTML, CSV, JSON.
}

interface

uses
  Winapi.Windows, Winapi.WinSock, Winapi.WinInet,
  System.SysUtils, System.Classes, System.Generics.Collections, System.Math,
  System.SyncObjs, System.StrUtils, System.IOUtils, System.JSON, Vcl.Dialogs,
  Vcl.Forms, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.Controls,
  Vcl.Samples.Spin;

type
  TScanResult = record
    IP: string;
    Port: Integer;
    IsOpen: Boolean;
    ResponseTime: Integer;
  end;

  TForm1 = class(TForm)
    Panel1: TPanel;
    EditIP: TEdit;
    BtnStart: TButton;
    BtnMyIP: TButton;
    SpinStart: TSpinEdit;
    SpinEnd: TSpinEdit;
    ListBoxResults: TListBox;
    ProgressBar: TProgressBar;
    StatusBar: TStatusBar;
    LabelOpen: TLabel;

    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure BtnStartClick(Sender: TObject);
    procedure BtnMyIPClick(Sender: TObject);
    procedure EditIPKeyPress(Sender: TObject; var Key: Char);

  private
    FStartTime: TDateTime;
    FIsScanning: Boolean;
    FWinSockStarted: Boolean;
    FActualWorkerCount: Integer;
    procedure UpdateStatusText(const Text: string);
    procedure AddScanProgress(ADoneCount: Integer; const AResult: TScanResult;
      AHasOpenResult: Boolean);
    procedure WorkerFinished(AThread: TObject);
    procedure ScanFinished;
    procedure ScanStopped;
    procedure RequestScanCancel(AClearQueue: Boolean);
    function IsScanCancelled: Boolean;
    procedure StopWorkersAndWait;
    procedure CleanupFinishedWorkers(AExceptThread: TThread);
    procedure SetScanControls(AScanning: Boolean; AStopping: Boolean);
    procedure AddOpenResultToView(const AResult: TScanResult);
    function FormatResultLine(AIndex: Integer; const AResult: TScanResult)
      : string;
    function TryReadTarget(out AHost: u_long): Boolean;
    function GetReportsDirectory: string;
  public
    procedure ExportResultsToHTML(const FileName: string);
    procedure ExportResultsToCSV(const FileName: string);
    procedure ExportResultsToJSON(const FileName: string);
    procedure ExportAllReports;
  end;

  TPortWorker = class(TThread)
  private
    FIP: string;
    FHost: u_long;
    FReportDoneCount: Integer;
    FReportHasOpenResult: Boolean;
    FReportResult: TScanResult;
    procedure DoReport;
    procedure DoNotifyFinished;
    function ScanPort(Port: Integer; out ResponseTime: Integer): Boolean;
    procedure FlushProgress(var APendingDone: Integer;
      const AResult: TScanResult; AHasOpenResult: Boolean);
  protected
    procedure Execute; override;
  public
    constructor Create(const AIP: string; AHost: u_long);
  end;

const
  MAX_WORKERS = 256;
  CONNECT_TIMEOUT_MS = 1500;
  PROGRESS_UPDATE_BATCH = 32;
  PROGRESS_UPDATE_INTERVAL_MS = 250;
  MIN_PORT_NUMBER = 1;
  MAX_PORT_NUMBER = 65535;
  RESULT_HEADER_LINES = 2;
  EXTERNAL_IP_TIMEOUT_MS = 5000;
  MAX_EXTERNAL_IP_RESPONSE_BYTES = 128;
  REPORT_FOLDER_NAME = 'PortScanner Reports';

var
  Form1: TForm1;
  FWSAData: TWSAData;
  Workers: array of TPortWorker;
  PortQueue: TQueue<Integer>;
  QueueCS: TCriticalSection;

  ScanResults: TList<TScanResult>;
  TotalPorts: Integer;
  DonePorts: Integer;
  OpenPorts: Integer;
  ActiveWorkers: Integer;
  CancelScan: Boolean;

implementation

{$R *.dfm}

function HtmlEncode(const Text: string): string;
begin
  Result := StringReplace(Text, '&', '&amp;', [rfReplaceAll]);
  Result := StringReplace(Result, '<', '&lt;', [rfReplaceAll]);
  Result := StringReplace(Result, '>', '&gt;', [rfReplaceAll]);
  Result := StringReplace(Result, '"', '&quot;', [rfReplaceAll]);
  Result := StringReplace(Result, '''', '&#39;', [rfReplaceAll]);
end;

function CsvEncode(const Text: string): string;
begin
  Result := StringReplace(Text, '"', '""', [rfReplaceAll]);
  if (Pos(',', Result) > 0) or (Pos('"', Text) > 0) or
    (Pos(#10, Result) > 0) or (Pos(#13, Result) > 0) then
    Result := '"' + Result + '"';
end;

function IsDigitsOnly(const Text: string): Boolean;
var
  Ch: Char;
begin
  Result := Text <> '';
  if not Result then
    Exit;

  for Ch in Text do
  begin
    if not ((Ch >= '0') and (Ch <= '9')) then
      Exit(False);
  end;
end;

function TryParseIPv4Address(const Text: string; out Host: u_long): Boolean;
var
  Parts: TArray<string>;
  I: Integer;
  Value: Integer;
  Normalized: string;
begin
  Result := False;
  Host := 0;
  Normalized := Trim(Text);
  Parts := SplitString(Normalized, '.');

  if Length(Parts) <> 4 then
    Exit;

  for I := 0 to High(Parts) do
  begin
    if (Parts[I] = '') or (Length(Parts[I]) > 3) or
      not IsDigitsOnly(Parts[I]) or not TryStrToInt(Parts[I], Value) or
      (Value < 0) or (Value > 255) then
      Exit;
  end;

  Host := inet_addr(PAnsiChar(AnsiString(Normalized)));
  Result := (Host <> u_long(INADDR_NONE)) and (Normalized <> '0.0.0.0');
end;

function TryDequeuePort(out Port: Integer): Boolean;
begin
  Result := False;
  Port := -1;

  if QueueCS = nil then
    Exit;

  QueueCS.Enter;
  try
    if CancelScan or (PortQueue = nil) or (PortQueue.Count = 0) then
      Exit;

    Port := PortQueue.Dequeue;
    Result := True;
  finally
    QueueCS.Leave;
  end;
end;

function IsCancellationRequested: Boolean;
begin
  Result := True;
  if QueueCS = nil then
    Exit;

  QueueCS.Enter;
  try
    Result := CancelScan;
  finally
    QueueCS.Leave;
  end;
end;

{ TPortWorker }

constructor TPortWorker.Create(const AIP: string; AHost: u_long);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FIP := AIP;
  FHost := AHost;
end;

procedure TPortWorker.DoReport;
begin
  if Assigned(Form1) then
    Form1.AddScanProgress(FReportDoneCount, FReportResult,
      FReportHasOpenResult);
end;

procedure TPortWorker.DoNotifyFinished;
begin
  if Assigned(Form1) then
    Form1.WorkerFinished(Self);
end;

procedure TPortWorker.FlushProgress(var APendingDone: Integer;
  const AResult: TScanResult; AHasOpenResult: Boolean);
begin
  if APendingDone <= 0 then
    Exit;

  FReportDoneCount := APendingDone;
  FReportResult := AResult;
  FReportHasOpenResult := AHasOpenResult;
  APendingDone := 0;
  Synchronize(DoReport);
end;

function TPortWorker.ScanPort(Port: Integer; out ResponseTime: Integer)
  : Boolean;
var
  Sock: TSocket;
  Addr: TSockAddrIn;
  NonBlocking: u_long;
  WriteSet, ErrSet: TFDSet;
  Timeout: TTimeVal;
  SelectResult: Integer;
  SocketError: Integer;
  ErrorLength: Integer;
  StartTick: UInt64;
begin
  Result := False;
  ResponseTime := -1;

  Sock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if Sock = INVALID_SOCKET then
    Exit;

  try
    NonBlocking := 1;
    if ioctlsocket(Sock, FIONBIO, NonBlocking) <> 0 then
      Exit;

    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(Port);
    Addr.sin_addr.S_addr := FHost;

    StartTick := GetTickCount64;

    if connect(Sock, Addr, SizeOf(Addr)) = SOCKET_ERROR then
    begin
      SocketError := WSAGetLastError;
      if SocketError <> WSAEWOULDBLOCK then
        Exit;
    end;

    FD_ZERO(WriteSet);
    FD_ZERO(ErrSet);
    FD_SET(Sock, WriteSet);
    FD_SET(Sock, ErrSet);

    Timeout.tv_sec := CONNECT_TIMEOUT_MS div 1000;
    Timeout.tv_usec := (CONNECT_TIMEOUT_MS mod 1000) * 1000;

    SelectResult := select(0, nil, @WriteSet, @ErrSet, @Timeout);
    if SelectResult <= 0 then
      Exit;

    ErrorLength := SizeOf(SocketError);
    SocketError := 0;
    if getsockopt(Sock, SOL_SOCKET, SO_ERROR, PAnsiChar(@SocketError),
      ErrorLength) <> 0 then
      Exit;

    if (SocketError = 0) and FD_ISSET(Sock, WriteSet) and
      not FD_ISSET(Sock, ErrSet) then
    begin
      Result := True;
      ResponseTime := Integer(GetTickCount64 - StartTick);
    end;
  finally
    closesocket(Sock);
  end;
end;

procedure TPortWorker.Execute;
var
  Port: Integer;
  Success: Boolean;
  RT: Integer;
  PendingDone: Integer;
  LastProgressTick: UInt64;
  ResultInfo: TScanResult;
begin
  PendingDone := 0;
  LastProgressTick := GetTickCount64;
  FillChar(ResultInfo, SizeOf(ResultInfo), 0);

  while not Terminated do
  begin
    if not TryDequeuePort(Port) then
      Break;

    Success := ScanPort(Port, RT);

    ResultInfo.IP := FIP;
    ResultInfo.Port := Port;
    ResultInfo.IsOpen := Success;
    if Success then
      ResultInfo.ResponseTime := RT
    else
      ResultInfo.ResponseTime := 0;

    Inc(PendingDone);

    if Success then
    begin
      FlushProgress(PendingDone, ResultInfo, True);
      LastProgressTick := GetTickCount64;
    end
    else if (PendingDone >= PROGRESS_UPDATE_BATCH) or
      (GetTickCount64 - LastProgressTick >= PROGRESS_UPDATE_INTERVAL_MS) then
    begin
      FlushProgress(PendingDone, ResultInfo, False);
      LastProgressTick := GetTickCount64;
    end;

    if IsCancellationRequested then
      Break;
  end;

  FlushProgress(PendingDone, ResultInfo, False);
  Synchronize(DoNotifyFinished);
end;

function GetLocalIPAddress: string;
var
  HostName: array [0 .. 255] of AnsiChar;
  HostEnt: PHostEnt;
  Addr: PInAddr;
begin
  Result := '127.0.0.1';
  if gethostname(HostName, SizeOf(HostName)) = SOCKET_ERROR then
    Exit;
  HostEnt := gethostbyname(HostName);
  if HostEnt = nil then
    Exit;
  Addr := PInAddr(HostEnt^.h_addr_list^);
  if Addr <> nil then
    Result := string(inet_ntoa(Addr^));
end;

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
var
  WSAResult: Integer;
begin
  QueueCS := TCriticalSection.Create;
  PortQueue := TQueue<Integer>.Create;
  ScanResults := TList<TScanResult>.Create;
  ListBoxResults.Font.Name := 'Consolas';
  ListBoxResults.Font.Size := 10;

  WSAResult := WSAStartup(MAKEWORD(2, 2), FWSAData);
  FWinSockStarted := WSAResult = 0;
  if not FWinSockStarted then
  begin
    ShowMessage('WinSock initialization failed. Error: ' + IntToStr(WSAResult));
    BtnStart.Enabled := False;
    BtnMyIP.Enabled := False;
    Application.Terminate;
    Exit;
  end;

  SpinStart.Value := MIN_PORT_NUMBER;
  SpinEnd.Value := MAX_PORT_NUMBER;
  EditIP.Text := GetLocalIPAddress;

  FIsScanning := False;
  FActualWorkerCount := 0;
  CancelScan := False;
  ActiveWorkers := 0;
  DonePorts := 0;
  OpenPorts := 0;
  TotalPorts := 0;

  ListBoxResults.Items.Add('ID  IP              PORT   STATE   RESPONSE');
  ListBoxResults.Items.Add('--------------------------------------------');
  SetScanControls(False, False);
  UpdateStatusText('Ready to scan');
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  StopWorkersAndWait;

  if FWinSockStarted then
    WSACleanup;

  FreeAndNil(PortQueue);
  FreeAndNil(QueueCS);
  FreeAndNil(ScanResults);
end;

procedure TForm1.RequestScanCancel(AClearQueue: Boolean);
begin
  if QueueCS = nil then
    Exit;

  QueueCS.Enter;
  try
    CancelScan := True;
    if AClearQueue and Assigned(PortQueue) then
      PortQueue.Clear;
  finally
    QueueCS.Leave;
  end;
end;

function TForm1.IsScanCancelled: Boolean;
begin
  Result := IsCancellationRequested;
end;

procedure TForm1.StopWorkersAndWait;
var
  HasRunningWorkers: Boolean;
  I: Integer;
begin
  RequestScanCancel(True);

  repeat
    HasRunningWorkers := False;
    for I := 0 to High(Workers) do
    begin
      if Assigned(Workers[I]) and not Workers[I].Finished then
      begin
        HasRunningWorkers := True;
        Break;
      end;
    end;

    if HasRunningWorkers then
      CheckSynchronize(50);
  until not HasRunningWorkers;

  CleanupFinishedWorkers(nil);
  SetLength(Workers, 0);
  ActiveWorkers := 0;
  FIsScanning := False;
end;

procedure TForm1.CleanupFinishedWorkers(AExceptThread: TThread);
var
  I: Integer;
begin
  for I := 0 to High(Workers) do
  begin
    if Assigned(Workers[I]) and (Workers[I] <> AExceptThread) and
      Workers[I].Finished then
      FreeAndNil(Workers[I]);
  end;
end;

procedure TForm1.SetScanControls(AScanning: Boolean; AStopping: Boolean);
begin
  EditIP.Enabled := not AScanning;
  SpinStart.Enabled := not AScanning;
  SpinEnd.Enabled := not AScanning;
  BtnMyIP.Enabled := not AScanning;
  BtnStart.Enabled := not AStopping;

  if AScanning then
    BtnStart.Caption := 'Stop'
  else
    BtnStart.Caption := 'Start';
end;

function TForm1.TryReadTarget(out AHost: u_long): Boolean;
var
  IPText: string;
begin
  IPText := Trim(EditIP.Text);
  Result := TryParseIPv4Address(IPText, AHost);
  if not Result then
    ShowMessage('Enter a valid numeric IPv4 address.');
end;

procedure TForm1.BtnStartClick(Sender: TObject);
var
  StartPort, EndPort: Integer;
  Host: u_long;
  WorkerCount: Integer;
  I, Port: Integer;
  IPText: string;
begin
  if FIsScanning then
  begin
    RequestScanCancel(True);
    UpdateStatusText('Stopping scan...');
    SetScanControls(True, True);
    Exit;
  end;

  CleanupFinishedWorkers(nil);
  SetLength(Workers, 0);

  ListBoxResults.Items.BeginUpdate;
  try
    ListBoxResults.Clear;
    ListBoxResults.Items.Add('ID  IP              PORT   STATE   RESPONSE');
    ListBoxResults.Items.Add('--------------------------------------------');
  finally
    ListBoxResults.Items.EndUpdate;
  end;

  ProgressBar.Position := 0;
  ScanResults.Clear;
  DonePorts := 0;
  OpenPorts := 0;
  LabelOpen.Caption := 'Open Ports: 0';

  StartPort := SpinStart.Value;
  EndPort := SpinEnd.Value;

  if (StartPort < MIN_PORT_NUMBER) or (EndPort < MIN_PORT_NUMBER) or
    (StartPort > MAX_PORT_NUMBER) or (EndPort > MAX_PORT_NUMBER) or
    (StartPort > EndPort) then
  begin
    ShowMessage('Enter a valid port range from 1 to 65535.');
    Exit;
  end;

  if not TryReadTarget(Host) then
    Exit;

  IPText := Trim(EditIP.Text);

  QueueCS.Enter;
  try
    CancelScan := False;
    PortQueue.Clear;
    for Port := StartPort to EndPort do
      PortQueue.Enqueue(Port);
  finally
    QueueCS.Leave;
  end;

  TotalPorts := EndPort - StartPort + 1;
  FStartTime := Now;

  WorkerCount := Min(TotalPorts, MAX_WORKERS);
  if WorkerCount < 1 then
    WorkerCount := 1;

  FActualWorkerCount := WorkerCount;
  ActiveWorkers := WorkerCount;
  SetLength(Workers, WorkerCount);

  for I := 0 to WorkerCount - 1 do
    Workers[I] := TPortWorker.Create(IPText, Host);

  FIsScanning := True;
  SetScanControls(True, False);
  UpdateStatusText(Format('Scanning %d ports with %d workers...',
    [TotalPorts, WorkerCount]));

  for I := 0 to WorkerCount - 1 do
    Workers[I].Start;
end;

procedure TForm1.BtnMyIPClick(Sender: TObject);
var
  hInet: HINTERNET;
  hFile: HINTERNET;
  Buffer: array [0 .. 1023] of AnsiChar;
  BytesRead: DWORD;
  Timeout: DWORD;
  Url: string;
  Content: AnsiString;
  Chunk: AnsiString;
  IPText: string;
  Host: u_long;
begin
  BtnMyIP.Enabled := False;
  try
    Url := 'https://icanhazip.com/';
    Timeout := EXTERNAL_IP_TIMEOUT_MS;
    hInet := InternetOpen('PortScanner', INTERNET_OPEN_TYPE_PRECONFIG, nil,
      nil, 0);
    if hInet = nil then
    begin
      ShowMessage('Failed to initialize the internet connection.');
      Exit;
    end;

    try
      InternetSetOption(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, @Timeout,
        SizeOf(Timeout));
      InternetSetOption(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, @Timeout,
        SizeOf(Timeout));
      InternetSetOption(hInet, INTERNET_OPTION_SEND_TIMEOUT, @Timeout,
        SizeOf(Timeout));

      hFile := InternetOpenUrl(hInet, PChar(Url), nil, 0,
        INTERNET_FLAG_RELOAD or INTERNET_FLAG_NO_CACHE_WRITE, 0);
      if hFile = nil then
      begin
        ShowMessage('Failed to retrieve the external IP address.');
        Exit;
      end;

      try
        Content := '';
        repeat
          BytesRead := 0;
          if not InternetReadFile(hFile, @Buffer[0], SizeOf(Buffer),
            BytesRead) then
          begin
            ShowMessage('Error reading the external IP response.');
            Exit;
          end;

          if BytesRead > 0 then
          begin
            SetString(Chunk, PAnsiChar(@Buffer[0]), BytesRead);
            Content := Content + Chunk;
            if Length(Content) > MAX_EXTERNAL_IP_RESPONSE_BYTES then
            begin
              ShowMessage('External IP response is too large.');
              Exit;
            end;
          end;
        until BytesRead = 0;

        IPText := Trim(string(Content));
        if not TryParseIPv4Address(IPText, Host) then
        begin
          ShowMessage('External service did not return a valid IPv4 address.');
          Exit;
        end;

        EditIP.Text := IPText;
        UpdateStatusText('External IPv4 address detected.');
      finally
        InternetCloseHandle(hFile);
      end;
    finally
      InternetCloseHandle(hInet);
    end;
  finally
    BtnMyIP.Enabled := not FIsScanning;
  end;
end;

procedure TForm1.EditIPKeyPress(Sender: TObject; var Key: Char);
begin
  if not (((Key >= '0') and (Key <= '9')) or (Key = '.') or (Key = #8)) then
    Key := #0;
end;

procedure TForm1.UpdateStatusText(const Text: string);
begin
  if StatusBar.Panels.Count > 0 then
    StatusBar.Panels[0].Text := Text;
end;

function TForm1.FormatResultLine(AIndex: Integer; const AResult: TScanResult)
  : string;
begin
  Result := Format('%-3d %-15s %-6d %-6s [%4d ms]',
    [AIndex + 1, AResult.IP, AResult.Port, 'OPEN', AResult.ResponseTime]);
end;

procedure TForm1.AddOpenResultToView(const AResult: TScanResult);
var
  InsertIndex, I: Integer;
begin
  InsertIndex := 0;
  while (InsertIndex < ScanResults.Count) and
    (ScanResults[InsertIndex].Port < AResult.Port) do
    Inc(InsertIndex);

  ScanResults.Insert(InsertIndex, AResult);

  ListBoxResults.Items.BeginUpdate;
  try
    ListBoxResults.Items.Insert(InsertIndex + RESULT_HEADER_LINES,
      FormatResultLine(InsertIndex, AResult));

    for I := InsertIndex + 1 to ScanResults.Count - 1 do
      ListBoxResults.Items[I + RESULT_HEADER_LINES] :=
        FormatResultLine(I, ScanResults[I]);
  finally
    ListBoxResults.Items.EndUpdate;
  end;

  if ListBoxResults.Items.Count > RESULT_HEADER_LINES then
    ListBoxResults.ItemIndex := ListBoxResults.Items.Count - 1;
end;

procedure TForm1.AddScanProgress(ADoneCount: Integer;
  const AResult: TScanResult; AHasOpenResult: Boolean);
var
  Elapsed: Double;
  Pct: Integer;
begin
  if ADoneCount <= 0 then
    Exit;

  Inc(DonePorts, ADoneCount);

  if AHasOpenResult and AResult.IsOpen then
  begin
    Inc(OpenPorts);
    AddOpenResultToView(AResult);
  end;

  if TotalPorts > 0 then
  begin
    Pct := Trunc(DonePorts * 100.0 / TotalPorts);
    ProgressBar.Position := EnsureRange(Pct, 0, 100);
  end;

  Elapsed := (Now - FStartTime) * 86400;
  if Elapsed > 0 then
    UpdateStatusText(Format('Scanned %d/%d ports (%d open) [%.1f ports/sec]',
      [DonePorts, TotalPorts, OpenPorts, DonePorts / Elapsed]))
  else
    UpdateStatusText(Format('Scanned %d/%d ports (%d open)',
      [DonePorts, TotalPorts, OpenPorts]));

  LabelOpen.Caption := 'Open Ports: ' + IntToStr(OpenPorts);
end;

procedure TForm1.ScanStopped;
var
  TotalTime: Double;
begin
  FIsScanning := False;
  SetScanControls(False, False);
  TotalTime := (Now - FStartTime) * 86400;
  UpdateStatusText(Format('Scan stopped. %d open ports found. Time: %.2f sec',
    [OpenPorts, TotalTime]));
end;

procedure TForm1.WorkerFinished(AThread: TObject);
begin
  CleanupFinishedWorkers(TThread(AThread));

  if ActiveWorkers > 0 then
    Dec(ActiveWorkers);

  if ActiveWorkers = 0 then
  begin
    if IsScanCancelled then
      ScanStopped
    else
      ScanFinished;
  end;
end;

procedure TForm1.ScanFinished;
var
  TotalTime: Double;
begin
  FIsScanning := False;
  SetScanControls(False, False);
  ProgressBar.Position := 100;

  TotalTime := (Now - FStartTime) * 86400;

  UpdateStatusText(Format('Scan finished. %d open ports found. Time: %.2f sec',
    [OpenPorts, TotalTime]));

  ExportAllReports;
end;

function TForm1.GetReportsDirectory: string;
begin
  Result := TPath.Combine(TPath.GetDocumentsPath, REPORT_FOLDER_NAME);
end;

procedure TForm1.ExportResultsToHTML(const FileName: string);
var
  SL: TStringList;
  R: TScanResult;
  I: Integer;
begin
  SL := TStringList.Create;
  try
    SL.Add('<!DOCTYPE html>');
    SL.Add('<html lang="en">');
    SL.Add('<head>');
    SL.Add('<meta charset="utf-8">');
    SL.Add('<title>Port Scan Results</title>');
    SL.Add('<style>');
    SL.Add('body { font-family: Arial, sans-serif; margin: 20px; }');
    SL.Add('table { border-collapse: collapse; width: 100%; }');
    SL.Add('th, td { border: 1px solid #ddd; padding: 8px; }');
    SL.Add('th { background-color: #f2f2f2; }');
    SL.Add('</style>');
    SL.Add('</head>');
    SL.Add('<body>');

    SL.Add('<h1>Port Scan Results</h1>');
    SL.Add('<p>Generated: ' + HtmlEncode(FormatDateTime('yyyy-mm-dd hh:nn:ss',
      Now)) + '</p>');
    SL.Add('<p>Target: ' + HtmlEncode(EditIP.Text) + '</p>');
    SL.Add('<p>Port range: ' + IntToStr(SpinStart.Value) + ' - ' +
      IntToStr(SpinEnd.Value) + '</p>');
    SL.Add('<p>Workers: ' + IntToStr(FActualWorkerCount) + '</p>');

    SL.Add('<table>');
    SL.Add('<tr><th>#</th><th>IP</th><th>Port</th><th>Response Time (ms)</th></tr>');

    for I := 0 to ScanResults.Count - 1 do
    begin
      R := ScanResults[I];
      SL.Add(Format('<tr><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>',
        [I + 1, HtmlEncode(R.IP), R.Port, R.ResponseTime]));
    end;

    SL.Add('</table>');
    SL.Add('</body>');
    SL.Add('</html>');
    SL.SaveToFile(FileName, TEncoding.UTF8);
  finally
    SL.Free;
  end;
end;

procedure TForm1.ExportResultsToCSV(const FileName: string);
var
  SL: TStringList;
  R: TScanResult;
  I: Integer;
begin
  SL := TStringList.Create;
  try
    SL.Add('Index,IP,Port,ResponseTimeMs');

    for I := 0 to ScanResults.Count - 1 do
    begin
      R := ScanResults[I];
      SL.Add(Format('%s,%s,%s,%s', [CsvEncode(IntToStr(I + 1)),
        CsvEncode(R.IP), CsvEncode(IntToStr(R.Port)),
        CsvEncode(IntToStr(R.ResponseTime))]));
    end;

    SL.SaveToFile(FileName, TEncoding.UTF8);
  finally
    SL.Free;
  end;
end;

procedure TForm1.ExportResultsToJSON(const FileName: string);
var
  Root: TJSONObject;
  Info: TJSONObject;
  Results: TJSONArray;
  Item: TJSONObject;
  R: TScanResult;
  I: Integer;
begin
  Root := TJSONObject.Create;
  try
    Info := TJSONObject.Create;
    Info.AddPair('date', FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));
    Info.AddPair('total_ports', TJSONNumber.Create(TotalPorts));
    Info.AddPair('open_ports', TJSONNumber.Create(OpenPorts));
    Info.AddPair('workers', TJSONNumber.Create(FActualWorkerCount));
    Root.AddPair('scan_info', Info);

    Results := TJSONArray.Create;
    for I := 0 to ScanResults.Count - 1 do
    begin
      R := ScanResults[I];
      Item := TJSONObject.Create;
      Item.AddPair('index', TJSONNumber.Create(I + 1));
      Item.AddPair('ip', R.IP);
      Item.AddPair('port', TJSONNumber.Create(R.Port));
      Item.AddPair('response_time', TJSONNumber.Create(R.ResponseTime));
      Results.AddElement(Item);
    end;
    Root.AddPair('results', Results);

    TFile.WriteAllText(FileName, Root.ToJSON, TEncoding.UTF8);
  finally
    Root.Free;
  end;
end;

procedure TForm1.ExportAllReports;
var
  BaseName, HTMLName, CSVName, JSONName: string;
  ReportsDir: string;
begin
  try
    ReportsDir := GetReportsDirectory;
    TDirectory.CreateDirectory(ReportsDir);

    BaseName := Format('portscan_%s_%s',
      [FormatDateTime('yyyymmdd_hhnnss', Now), StringReplace(Trim(EditIP.Text),
      '.', '_', [rfReplaceAll])]);

    HTMLName := TPath.Combine(ReportsDir, BaseName + '.html');
    CSVName := TPath.Combine(ReportsDir, BaseName + '.csv');
    JSONName := TPath.Combine(ReportsDir, BaseName + '.json');

    ExportResultsToHTML(HTMLName);
    ExportResultsToCSV(CSVName);
    ExportResultsToJSON(JSONName);

    UpdateStatusText(Format('Reports exported to %s', [ReportsDir]));
  except
    on E: Exception do
      ShowMessage('Error exporting reports: ' + E.Message);
  end;
end;

end.
