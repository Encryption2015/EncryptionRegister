unit UnitMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
   StdCtrls, ExtCtrls,untWaterEffect, WinSkinData,Dialogs,EncodeStrFuns;
  const
    MesAge1='D7A2B2E1B3C9B9A6A3A1CAB9D3C3CADAC8A8D3DAA3BA';
    MesAge2='D7A2B2E1C2EBB4EDCEF3A3ACC7EBD3EBC8EDBCFEBFAAB7A2C9CCC1AACFB5A3A1';
    MesAgeTile='CCE1CABE';
type
  TFrmMain = class(TForm)
    Edit_ID: TEdit;
    Edit_Name: TEdit;
    BtnOK: TButton;
    Edit_Code: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Timer1: TTimer;
    Image1: TImage;
    SkinData1: TSkinData;
    procedure BtnOKClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Image1MouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Integer);
    procedure FormDestroy(Sender: TObject);
  private
    Water: TWaterEffect;
    Bmp: TBitmap;
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FrmMain: TFrmMain;
  x:integer;
  var Img:TImage;
implementation
   uses CantBPAPI;
{$R *.dfm}
function AntiLoader():Boolean;
var
  Info:STARTUPINFO;
begin
  GetStartupInfo(Info);
  if (Info.dwX<>0) or (Info.dwY<>0) or (Info.dwXCountChars<>0) or (Info.dwYCountChars<>0) or
     (Info.dwFillAttribute<>0) or (Info.dwXSize<>0) or (Info.dwYSize<>0) then
    Result:=True
  else
    Result:=False;
end;

function SiftStr(Str: string): Boolean;  //过滤字符串
  var i,j:integer;
begin
    Result:=false;
    j:=Length(str);
    if j<1 then
      begin
       abort;
      end;
    for i:=0 to j do
    begin
    Result:=str[i] in ['b'..'y','B'..'Y'];
    end;
end;  

function myHextoStr(S: string): string;           //16进制字符串转原字符串
var hexS,tmpstr:string;
    i:integer;
    a:byte;
begin
    hexS  :=s;//应该是该字符串
    if length(hexS) mod 2=1 then
    begin
        hexS:=hexS+'0';
    end;
    tmpstr:='';
    for i:=1 to (length(hexS) div 2) do
    begin
        a:=strtoint('$'+hexS[2*i-1]+hexS[2*i]);
        tmpstr := tmpstr+chr(a);
    end;
    result :=tmpstr;
end;

function StrToASCII10(s: string): string;    //字符串转换ascii码10进制
var i:integer;
begin
    for i:=1 to length(s) do
    begin
    result:= result + inttostr(ord(s[i]));
    end;
end;

function GetClientRegCode(Str: string): string;
var
  S: string;
  K, I, Len: integer;
begin
  if Length(Str) < 4 then
    Exit;
  S:= StrToASCII10(Str);
  Len:= Length(S);
  if Len > 0 then
  begin
    K:= StrToInt(S[Length(S)]);
    Result:= '';
    for I:= 1 to Len - 1 do
      Result:= Result + IntToStr((StrToInt(S[I]) + K) mod 10);
    S:= Result;     Result:= '';
    for I:= 1 to 4 do
      Result:= Result + Copy(S, Len - I * 5, 5) + '-';
    Result:= Result + Copy(S, Len - 25, 5);
  end;
end;

function ReadPassWord(imgOrig1,imgTarget1:TImage):string;     //读取密码
var
  x, y              : integer;
  mask, ch          : byte;
begin
  Result:='';
  mask := $80;
  ch := 0;
  for y := 0 to imgOrig1.Picture.Bitmap.Height - 1 do
  begin
    for x := 0 to imgOrig1.Picture.Bitmap.Width - 1 do
    begin
       if (imgOrig1.Picture.Bitmap.Canvas.Pixels[x, y] <>
        imgTarget1.Picture.Bitmap.Canvas.Pixels[x, y]) then
        ch := ch or mask;
      mask := mask shr 1;
      if mask = 0 then
      begin
        Result := Result + char(ch);
        mask := $80;
        ch := 0;
      end;
    end;
  end;
end;

//取硬盘系列号:
function GetIdeSerialNumber: pchar;  //获取硬盘的出厂系列号；
  const IDENTIFY_BUFFER_SIZE = 512;
type
   TIDERegs = packed record
     bFeaturesReg: BYTE;
     bSectorCountReg: BYTE;
     bSectorNumberReg: BYTE;
     bCylLowReg: BYTE;
     bCylHighReg: BYTE;
     bDriveHeadReg: BYTE;
     bCommandReg: BYTE;
     bReserved: BYTE;
  end;
  TSendCmdInParams = packed record
    cBufferSize: DWORD;
    irDriveRegs: TIDERegs;
    bDriveNumber: BYTE;
    bReserved: array[0..2] of Byte;
    dwReserved: array[0..3] of DWORD;
    bBuffer: array[0..0] of Byte;
  end;
  TIdSector = packed record
    wGenConfig: Word;
    wNumCyls: Word;
    wReserved: Word;
    wNumHeads: Word;
    wBytesPerTrack: Word;
    wBytesPerSector: Word;
    wSectorsPerTrack: Word;
    wVendorUnique: array[0..2] of Word;
    sSerialNumber: array[0..19] of CHAR;
    wBufferType: Word;
    wBufferSize: Word;
    wECCSize: Word;
    sFirmwareRev: array[0..7] of Char;
    sModelNumber: array[0..39] of Char;
    wMoreVendorUnique: Word;
    wDoubleWordIO: Word;
    wCapabilities: Word;
    wReserved1: Word;
    wPIOTiming: Word;
    wDMATiming: Word;
    wBS: Word;
    wNumCurrentCyls: Word;
    wNumCurrentHeads: Word;
    wNumCurrentSectorsPerTrack: Word;
    ulCurrentSectorCapacity: DWORD;
    wMultSectorStuff: Word;
    ulTotalAddressableSectors: DWORD;
    wSingleWordDMA: Word;
    wMultiWordDMA: Word;
    bReserved: array[0..127] of BYTE;
  end;
  PIdSector = ^TIdSector;
  TDriverStatus = packed record
    bDriverError: Byte;
    bIDEStatus: Byte;
    bReserved: array[0..1] of Byte;
    dwReserved: array[0..1] of DWORD;
  end;
  TSendCmdOutParams = packed record
    cBufferSize: DWORD;
    DriverStatus: TDriverStatus;
    bBuffer: array[0..0] of BYTE;
  end;
var
  hDevice: Thandle;
  cbBytesReturned: DWORD;
  SCIP: TSendCmdInParams;
  aIdOutCmd: array[0..(SizeOf(TSendCmdOutParams) + IDENTIFY_BUFFER_SIZE-1)-1] of Byte;
  IdOutCmd: TSendCmdOutParams absolute aIdOutCmd;
procedure ChangeByteOrder(var Data; Size: Integer);
var
  ptr: Pchar;
  i: Integer;
  c: Char;
begin
  ptr := @Data;
  for I := 0 to (Size shr 1) - 1 do begin
    c := ptr^;
    ptr^ := (ptr + 1)^;
    (ptr + 1)^ := c;
    Inc(ptr, 2);
  end;
end;
begin
    Result := '';
    if SysUtils.Win32Platform = VER_PLATFORM_WIN32_NT then begin // Windows NT, Windows 2000
    hDevice := CreateFile('\\.\PhysicalDrive0', GENERIC_READ or GENERIC_WRITE,
    FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
    end else // Version Windows 95 OSR2, Windows 98
    hDevice := CreateFile('\\.\SMARTVSD', 0, 0, nil, CREATE_NEW, 0, 0);
    if hDevice = INVALID_HANDLE_VALUE then Exit;
    try
    FillChar(SCIP, SizeOf(TSendCmdInParams) - 1, #0);
    FillChar(aIdOutCmd, SizeOf(aIdOutCmd), #0);
    cbBytesReturned := 0;
    with SCIP do begin
    cBufferSize := IDENTIFY_BUFFER_SIZE;
    with irDriveRegs do begin
    bSectorCountReg := 1;
    bSectorNumberReg := 1;
    bDriveHeadReg := $A0;
    bCommandReg := $EC;
    end;
    end;
    if not DeviceIoControl(hDevice, $0007C088, @SCIP, SizeOf(TSendCmdInParams) - 1,
    @aIdOutCmd, SizeOf(aIdOutCmd), cbBytesReturned, nil) then Exit;
    finally
    CloseHandle(hDevice);
    end;
    with PIdSector(@IdOutCmd.bBuffer)^ do begin
    ChangeByteOrder(sSerialNumber, SizeOf(sSerialNumber));
    (Pchar(@sSerialNumber) + SizeOf(sSerialNumber))^:= #0;
    Result := Pchar(@sSerialNumber);
    end;
end;  

procedure TFrmMain.BtnOKClick(Sender: TObject);   
begin
      if AntiLoader then
      begin
         asm
          MOV EAX,DWORD PTR FS:[0]
      @L001:
        CMP DWORD PTR DS:[EAX],-1
        JE @L006
        MOV EAX,DWORD PTR DS:[EAX]
        MOV DWORD PTR FS:[0],EAX
        JMP @L001
      @L006:
        MOV EAX,DWORD PTR DS:[EAX+8]
        MOV EAX,DWORD PTR DS:[EAX+8]
        ADD EAX,13
        JMP EAX
         end;
      end;
      if (SiftStr(Edit_Name.Text))  and (Trim(ReadPassWord(Image1,Img))=Edit_Code.Text)
       and (StrBlueDecode(Edit_Code.Text)=Edit_Name.Text+Edit_ID.Text) then
      application.MessageBox(PChar(myHextoStr(MesAge1)+Edit_Name.text),PChar(myHextoStr(MesAgeTile)),MB_OK+64)
       else
      application.MessageBox(PChar(myHextoStr(MesAge2)),PChar(myHextoStr(MesAgeTile)),MB_OK+MB_IconError);
 end;


procedure TFrmMain.Timer1Timer(Sender: TObject);
begin
   if Random(22)= 1 then
    Water.Blob(-1,-1,Random(1)+1,Random(500)+50);
    Water.Render(Bmp,Image1.Picture.Bitmap);
   with Image1.Canvas do
    begin
      Brush.Style:=bsClear;
      font.size:=12;
      font.color:=$FFFFFF;
      TextOut((Bmp.Width - TextWidth(''))div 2+2,10,'');
    end;   
end;

procedure TFrmMain.FormCreate(Sender: TObject);
begin
     Bmp := TBitmap.Create;
    Bmp.Assign(Image1.Picture.Graphic);
    Image1.Picture.Graphic := nil;
    Image1.Picture.Bitmap.Height := Bmp.Height;
    Image1.Picture.Bitmap.Width := Bmp.Width;
    Water := TWaterEffect.Create;
    Water.SetSize(Bmp.Width,Bmp.Height);
    x:=Image1.Height;
       //==========动态创建图片
    Img:=TImage.Create(self);
    Img.parent:=self;
    Img.left:=0;
    Img.top:=-16;
    Img.width:=343;
    Img.Height:=96;
    Img.SendToBack;
    if FileExists('3w.bmp') then
    begin
      Img.Picture.LoadFromFile('3w.bmp'); //=========载入图片
    end;
    Edit_ID.Text:=GetClientRegCode(Trim(strpas(GetIdeSerialNumber))); //调用
end;

procedure TFrmMain.Image1MouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Integer);
begin
    Water.Blob(x,y,1,100);
end;

procedure TFrmMain.FormDestroy(Sender: TObject);
begin
  Bmp.Free;
  Water.Free;
end;

end.
