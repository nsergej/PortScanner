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
  Winapi.Windows, Winapi.Messages, Winapi.WinSock, Winapi.WinInet,
  System.Variants,
  System.SysUtils, System.Classes, System.Generics.Collections, System.Math,
  System.SyncObjs, System.DateUtils, System.StrUtils, Vcl.Dialogs,
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
    procedure ApplicationEvents1Message(var Msg: tagMSG; var Handled: Boolean);
    procedure UpdateStatusText(const Text: string);
    procedure AddScanResult(const Result: TScanResult);
    procedure WorkerFinished(AThread: TObject);
    procedure ScanFinished;
    procedure ScanStopped;
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
    FResult: TScanResult;
    procedure DoReport;
    procedure DoNotifyFinished;
    function ScanPort(Port: Integer; out ResponseTime: Integer): Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AIP: string; AHost: u_long);
  end;

const
  MAX_WORKERS = 256;
  CONNECT_TIMEOUT_MS = 1500;

var
  Form1: TForm1;
  FWSAData: TWSAData;
  Workers: array of TPortWorker;
  PortQueue: TQueue<Integer>;
  QueueCS: TCriticalSection;

  ScanResults: TList<TScanResult>; // только открытые порты
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

{ TPortWorker }

constructor TPortWorker.Create(const AIP: string; AHost: u_long);
begin
  inherited Create(False);
  FreeOnTerminate := True;
  FIP := AIP;
  FHost := AHost;
end;

procedure TPortWorker.DoReport;
begin
  Form1.AddScanResult(FResult);
end;

procedure TPortWorker.DoNotifyFinished;
begin
  Form1.WorkerFinished(Self);
end;

function TPortWorker.ScanPort(Port: Integer; out ResponseTime: Integer)
  : Boolean;
var
  Sock: TSocket;
  Addr: TSockAddrIn;
  Nb: u_long;
  WriteSet, ErrSet: TFDSet;
  Tv: TTimeVal;
  SelRes: Integer;
  Err: Integer;
  ErrLen: Integer;
  StartTick: Cardinal;
begin
  Result := False;
  ResponseTime := -1;

  Sock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if Sock = INVALID_SOCKET then
    Exit;

  try
    Nb := 1;
    if ioctlsocket(Sock, FIONBIO, Nb) <> 0 then
      Exit;

    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(Port);
    Addr.sin_addr.S_addr := FHost;

    StartTick := GetTickCount;

    if connect(Sock, Addr, SizeOf(Addr)) = SOCKET_ERROR then
    begin
      Err := WSAGetLastError;
      if Err <> WSAEWOULDBLOCK then
        Exit;
    end;

    FD_ZERO(WriteSet);
    FD_ZERO(ErrSet);
    FD_SET(Sock, WriteSet);
    FD_SET(Sock, ErrSet);

    Tv.tv_sec := CONNECT_TIMEOUT_MS div 1000;
    Tv.tv_usec := (CONNECT_TIMEOUT_MS mod 1000) * 1000;

    SelRes := select(0, nil, @WriteSet, @ErrSet, @Tv);

    if SelRes > 0 then
    begin
      ErrLen := SizeOf(Err);
      Err := 0;
      getsockopt(Sock, SOL_SOCKET, SO_ERROR, PAnsiChar(@Err), ErrLen);

      if (Err = 0) and FD_ISSET(Sock, WriteSet) and not FD_ISSET(Sock, ErrSet)
      then
      begin
        Result := True;
        ResponseTime := GetTickCount - StartTick;
      end;
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
begin
  while not Terminated do
  begin
    if CancelScan then
      Break;

    // Берём следующий порт из очереди
    QueueCS.Enter;
    try
      if CancelScan then
        Port := -1
      else if PortQueue.Count > 0 then
        Port := PortQueue.Dequeue
      else
        Port := -1;
    finally
      QueueCS.Leave;
    end;

    if Port = -1 then
      Break;

    Success := ScanPort(Port, RT);

    FResult.IP := FIP;
    FResult.Port := Port;
    FResult.IsOpen := Success;
    if Success then
      FResult.ResponseTime := RT
    else
      FResult.ResponseTime := 0;

    Synchronize(DoReport);

    if Terminated or CancelScan then
      Break;
  end;

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
  if WSAResult <> 0 then
  begin
    ShowMessage('Winsock initialization failed. Error: ' + IntToStr(WSAResult));
    Halt;
  end;

  SpinStart.Value := 1;
  SpinEnd.Value := 65535;
  EditIP.Text := GetLocalIPAddress;

  FIsScanning := False;
  CancelScan := False;
  ActiveWorkers := 0;

  Application.OnMessage := ApplicationEvents1Message;
  UpdateStatusText('Ready to scan');
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  CancelScan := True;
  WSACleanup;
  PortQueue.Free;
  QueueCS.Free;
  ScanResults.Free;
end;

procedure TForm1.ApplicationEvents1Message(var Msg: tagMSG;
  var Handled: Boolean);
begin
  Handled := False;
end;

procedure TForm1.BtnStartClick(Sender: TObject);
var
  StartPort, EndPort: Integer;
  Host: u_long;
  WorkerCount: Integer;
  I, Port: Integer;
begin
  // === STOP ===
  if FIsScanning then
  begin
    CancelScan := True;

    QueueCS.Enter;
    try
      PortQueue.Clear;
    finally
      QueueCS.Leave;
    end;

    UpdateStatusText('Stopping scan...');
    BtnStart.Enabled := False;
    Exit;
  end;

  // === START ===
  ListBoxResults.Clear;
  ProgressBar.Position := 0;
  ScanResults.Clear;
  DonePorts := 0;
  OpenPorts := 0;

  StartPort := SpinStart.Value;
  EndPort := SpinEnd.Value;

  if (StartPort < 1) or (EndPort < 1) or (StartPort > 65535) or
    (EndPort > 65535) or (StartPort > EndPort) then
  begin
    ShowMessage('Invalid port range');
    Exit;
  end;

  if Trim(EditIP.Text) = '' then
  begin
    ShowMessage('Enter IP address');
    Exit;
  end;

  Host := inet_addr(PAnsiChar(AnsiString(Trim(EditIP.Text))));
  if Host = u_long(INADDR_NONE) then
  begin
    ShowMessage('Invalid IP address');
    Exit;
  end;

  QueueCS.Enter;
  try
    PortQueue.Clear;
    for Port := StartPort to EndPort do
      PortQueue.Enqueue(Port);
  finally
    QueueCS.Leave;
  end;

  TotalPorts := EndPort - StartPort + 1;
  FStartTime := Now;
  CancelScan := False;

  WorkerCount := TotalPorts;
  if WorkerCount > MAX_WORKERS then
    WorkerCount := MAX_WORKERS;
  if WorkerCount < 1 then
    WorkerCount := 1;

  ActiveWorkers := WorkerCount;
  SetLength(Workers, WorkerCount);

  for I := 0 to WorkerCount - 1 do
    Workers[I] := TPortWorker.Create(Trim(EditIP.Text), Host);

  FIsScanning := True;
  BtnStart.Caption := 'Stop';

  UpdateStatusText(Format('Scanning %d ports with %d workers...',
    [TotalPorts, WorkerCount]));
end;

procedure TForm1.BtnMyIPClick(Sender: TObject);
var
  hInet: HINTERNET;
  hFile: HINTERNET;
  Buffer: array [0 .. 1023] of AnsiChar;
  BytesRead: DWORD;
  Url: string;
  Content: AnsiString;
begin
  BtnMyIP.Enabled := False;
  try
    try
      Url := 'https://icanhazip.com/';
      hInet := InternetOpen(PChar(Application.Title),
        INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);
      if hInet = nil then
      begin
        ShowMessage('Failed to initialize internet connection');
        Exit;
      end;

      try
        hFile := InternetOpenUrl(hInet, PChar(Url), nil, 0,
          INTERNET_FLAG_RELOAD or INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if hFile = nil then
        begin
          ShowMessage
            ('Failed to retrieve external IP. Check internet connection.');
          Exit;
        end;

        try
          Content := '';
          repeat
            if InternetReadFile(hFile, @Buffer[0], SizeOf(Buffer), BytesRead)
            then
            begin
              if BytesRead > 0 then
              begin
                SetString(Content, PAnsiChar(@Buffer[0]), BytesRead);
                EditIP.Text := Trim(string(Content));
              end;
            end
            else
            begin
              ShowMessage('Error reading response from server');
              Break;
            end;
          until BytesRead = 0;

          if EditIP.Text <> '' then
          else
            ShowMessage('Could not determine external IP');

        finally
          InternetCloseHandle(hFile);
        end;
      finally
        InternetCloseHandle(hInet);
      end;
    except
      on E: Exception do
        ShowMessage('Error getting external IP: ' + E.Message);
    end;
  finally
    BtnMyIP.Enabled := True;
  end;
end;

procedure TForm1.EditIPKeyPress(Sender: TObject; var Key: Char);
const
  AllowedChars: set of Char = ['0' .. '9', '.', #8];
begin
  if not CharInSet(Key, AllowedChars) then
    Key := #0;
end;

procedure TForm1.UpdateStatusText(const Text: string);
begin
  StatusBar.Panels[0].Text := Text;
end;

procedure TForm1.AddScanResult(const Result: TScanResult);
var
  Elapsed: Double;
  Pct: Integer;
  InsertIndex, I: Integer;
  R: TScanResult;
  Line: string;
begin
  Inc(DonePorts);

  if Result.IsOpen then
  begin
    Inc(OpenPorts);

    InsertIndex := 0;
    while (InsertIndex < ScanResults.Count) and
      (ScanResults[InsertIndex].Port < Result.Port) do
      Inc(InsertIndex);

    ScanResults.Insert(InsertIndex, Result);
    ListBoxResults.Items.BeginUpdate;
    try
      ListBoxResults.Clear;
      ListBoxResults.Items.Add('ID  IP              PORT   STATE   RESPONSE');
      ListBoxResults.Items.Add('--------------------------------------------');
      for I := 0 to ScanResults.Count - 1 do
      begin
        R := ScanResults[I];

        if R.ResponseTime >= 0 then
          Line := Format('%-3d %-15s %-6d %-6s [%4d ms]',
            [I + 1, R.IP, R.Port, 'OPEN', R.ResponseTime])
        else
          Line := Format('%d) %s:%d OPEN', [I + 1, R.IP, R.Port]);

        ListBoxResults.Items.Add(Line);
      end;

    finally
      ListBoxResults.Items.EndUpdate;
    end;

    if ListBoxResults.Items.Count > 0 then
      ListBoxResults.ItemIndex := ListBoxResults.Items.Count - 1;
  end;

  if TotalPorts > 0 then
  begin
    Pct := Trunc(DonePorts * 100.0 / TotalPorts);
    if Pct < 0 then
      Pct := 0;
    if Pct > 100 then
      Pct := 100;
    ProgressBar.Position := Pct;
  end;

  Elapsed := (Now - FStartTime) * 86400;

  if Elapsed > 0 then
    UpdateStatusText(Format('Scanned %d/%d ports (%d open) [%.1f ports/sec]',
      [DonePorts, TotalPorts, OpenPorts, DonePorts / Elapsed]))
  else
    UpdateStatusText(Format('Scanned %d/%d ports (%d open)',
      [DonePorts, TotalPorts, OpenPorts]));

  LabelOpen.Caption := 'Open Port: ' + IntToStr(OpenPorts);
end;

procedure TForm1.ScanStopped;
var
  TotalTime: Double;
begin
  FIsScanning := False;
  BtnStart.Enabled := True;
  BtnStart.Caption := 'Start';
  TotalTime := (Now - FStartTime) * 86400;
  UpdateStatusText(Format('Scan stopped. %d open ports found. Time: %.2f sec',
    [OpenPorts, TotalTime]));
end;

procedure TForm1.WorkerFinished(AThread: TObject);
begin
  if ActiveWorkers > 0 then
    Dec(ActiveWorkers);

  if ActiveWorkers = 0 then
  begin
    if CancelScan then
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
  BtnStart.Enabled := True;
  BtnStart.Caption := 'Start';
  ProgressBar.Position := 100;

  TotalTime := (Now - FStartTime) * 86400;

  UpdateStatusText(Format('Scan finished. %d open ports found. Time: %.2f sec',
    [OpenPorts, TotalTime]));

  ExportAllReports;
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
    SL.Add('<html><head>');
    SL.Add('<meta charset="utf-8">');
    SL.Add('<title>Port Scan Results</title>');
    SL.Add('<style>');
    SL.Add('body { font-family: Arial; margin: 20px; }');
    SL.Add('table { border-collapse: collapse; width: 100%; }');
    SL.Add('th, td { border: 1px solid #ddd; padding: 8px; }');
    SL.Add('th { background-color: #f2f2f2; }');
    SL.Add('</style>');
    SL.Add('</head><body>');

    SL.Add('<h1>Port Scan Results</h1>');
    SL.Add('<p>Generated: ' + FormatDateTime('yyyy-mm-dd hh:nn:ss', Now)
      + '</p>');
    SL.Add('<p>Target: ' + HtmlEncode(EditIP.Text) + '</p>');
    SL.Add('<p>Port range: ' + IntToStr(SpinStart.Value) + ' - ' +
      IntToStr(SpinEnd.Value) + '</p>');
    SL.Add('<p>Workers: ' + IntToStr(MAX_WORKERS) + '</p>');

    SL.Add('<table>');
    SL.Add('<tr><th>#</th><th>IP</th><th>Port</th><th>Response Time (ms)</th></tr>');

    for I := 0 to ScanResults.Count - 1 do
    begin
      R := ScanResults[I];
      SL.Add(Format('<tr><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>',
        [I + 1, HtmlEncode(R.IP), R.Port, R.ResponseTime]));
    end;

    SL.Add('</table>');
    SL.Add('</body></html>');
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
      SL.Add(Format('%d,%s,%d,%d', [I + 1, R.IP, R.Port, R.ResponseTime]));
    end;

    SL.SaveToFile(FileName, TEncoding.UTF8);
  finally
    SL.Free;
  end;
end;

procedure TForm1.ExportResultsToJSON(const FileName: string);
var
  SL: TStringList;
  R: TScanResult;
  I: Integer;
  Line: string;
begin
  SL := TStringList.Create;
  try
    SL.Add('{');
    SL.Add('  "scan_info": {');
    SL.Add('    "date": "' + FormatDateTime('yyyy-mm-dd hh:nn:ss', Now) + '",');
    SL.Add('    "total_ports": ' + IntToStr(TotalPorts) + ',');
    SL.Add('    "open_ports": ' + IntToStr(OpenPorts));
    SL.Add('  },');
    SL.Add('  "results": [');

    for I := 0 to ScanResults.Count - 1 do
    begin
      R := ScanResults[I];
      Line := Format
        ('    {"index": %d, "ip": "%s", "port": %d, "response_time": %d}',
        [I + 1, R.IP, R.Port, R.ResponseTime]);

      if I < ScanResults.Count - 1 then
        Line := Line + ',';

      SL.Add(Line);
    end;

    SL.Add('  ]');
    SL.Add('}');
    SL.SaveToFile(FileName, TEncoding.UTF8);
  finally
    SL.Free;
  end;
end;

procedure TForm1.ExportAllReports;
var
  BaseName, HTMLName, CSVName, JSONName: string;
begin
  try
    BaseName := Format('portscan_%s_%s',
      [FormatDateTime('yyyymmdd_hhnnss', Now), StringReplace(Trim(EditIP.Text),
      '.', '_', [rfReplaceAll])]);

    HTMLName := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0))) +
      BaseName + '.html';
    CSVName := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0))) +
      BaseName + '.csv';
    JSONName := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0))) +
      BaseName + '.json';

    ExportResultsToHTML(HTMLName);
    ExportResultsToCSV(CSVName);
    ExportResultsToJSON(JSONName);

    UpdateStatusText(Format('Reports exported: %s.*', [BaseName]));
  except
    on E: Exception do
      ShowMessage('Error exporting reports: ' + E.Message);
  end;
end;

end.
