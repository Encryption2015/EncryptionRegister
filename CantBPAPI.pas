//***********************��鵼������Ƿ��������ж�***********************//
//Author : Dazzling Blue ��ɫ��â                                             //
//2006-2-28 last update at www.1284.net                                       //
//���ܣ�������ĵ�������Ƿ������˶ϵ�(Ring 3�ϵ�)                      //
//      ������ֱ��������ж� ���ƻ���DestroyPointerָ���ĵ�ַ                 //
//�¿��߳̽��м�飬���ʱ������WaitTimeForCheckBPAPIָ��                   //
//���ʱ���������������DestroyPointer��ַ������Ӧ������һ��Ƶ�����õ�API��ַ //
//�÷�ʽDumpһ�����������                                                    //
//****************************************************************************//
unit CantBPAPI;

//���û��SMC_RES_Client��Ԫ����ע�͵��������С�SMC_RES_ClientΪ�������޸ĺͻ�ԭ
//{$Define SMC_RES_Client}

interface

Uses
  Windows , Messages
  {$IFDEF SMC_RES_Client}
  ,SMC_RES_Client
  {$ENDIF}
  ;

procedure CloseApplication;

//������� varCurrency ˵���Ѿ�������
Function GetChecked : WORD;

implementation

Const
  //���ʱ����
  WaitTimeForCheckBPAPI = 60 * 1000;  //60����һ��
  //�ƻ������ַ
  DestroyPointer : Pointer = @PeekMessage;


Type
  PIMAGE_IMPORT_DESCRIPTOR = ^TIMAGE_IMPORT_DESCRIPTOR;
  TIMAGE_IMPORT_DESCRIPTOR = packed Record
    OriginalFirstThunk    : DWORD;
    TimeDateStamp         : DWORD;
    ForwarderChain        : DWORD;
    Name                  : DWORD;
    FirstThunk            : DWORD;
  end;

function FinalFunctionAddress(Code: Pointer): Pointer;
begin
  Result := Code;
  if Code<>NIL then begin
    if (PWord(Code)^ - $25FF)=0 then
      Result := PPointer(PPointer(Pointer(DWORD(Code)+2))^)^;
  end;  
end;

procedure CloseApplication;
asm
  MOV  EAX , 9;
  CALL SysGetMem;
  MOV  Byte  Ptr [EAX], $E9;
  INC  EAX;
  PUSH EAX;
  MOV  DWORD Ptr [EAX], $8964C031; // XOR EAX,EAX; MOV FS:[0],EAX;
  ADD  EAX , 4;
  MOV  DWORD Ptr [EAX], $90008900; // MOV [EAX],EAX; NOP;

  XCHG EBX , [ESP];
  XOR  EAX , EAX;
  PUSH EAX;
  PUSH ESP;                             //ESP -> lpThreadId
  PUSH EAX;                             //dwCreationFlags
  PUSH EAX;                             //lpParameter
  PUSH EBX;                             //lpStartAddress
  PUSH EAX;                             //dwStackSize
  PUSH EAX;                             //lpThreadAttributes
  CALL CreateThread;                    //Create new thread
  ADD  ESP , 4;
  POP  EBX;
end;

procedure CloseApplication2;
asm
  MOV  EAX , 9;
  CALL SysGetMem;
  MOV  Byte  Ptr [EAX], $E9;
  INC  EAX;
  PUSH EAX;
  MOV  DWORD Ptr [EAX], $8964C031; // XOR EAX,EAX; MOV FS:[0],EAX;
  ADD  EAX , 4;
  MOV  DWORD Ptr [EAX], $90008900; // MOV [EAX],EAX; NOP;
  SUB  EAX , 4;
  ADD  ESP , $100;                 //�ƻ�ESP
  ADD  EBP , $100;                 //�ƻ�EBP
  JMP  EAX;
end;

//������е�������Ƿ������˶ϵ㣬��������Ӧ

Function CheckAllImportFunAdrs : integer;stdcall;
var
  SecBaseAdr  : DWORD;                     //����ַ
  NTHead      : PImageNtHeaders;           //
  ImportPoint : PIMAGE_IMPORT_DESCRIPTOR;  //
  P           : PByte;
  PD          : PDWORD;
  procedure ExitProcessNoBP;stdcall;
  asm
    XOR EAX , EAX;
    MOV FS:[EAX],EAX;
    MOV [EAX],EAX;
  end;
begin
  {$IFDEF SMC_RES_Client}
    {$i SMC_RES_Start.inc}
  {$ENDIF}
  P := FinalFunctionAddress(@DestroyPointer);
  if (P<>NIL) and (P^ = $CC) then begin
    CloseApplication;
  end;
  P := FinalFunctionAddress(@WriteProcessMemory);
  if (P<>NIL) and (P^ = $CC) then begin
    CloseApplication2;       //�������û�б��ص��Ļ����Ǿ�ֻ�ù㲥һ����Ϣ��
    PostMessage(HWND_BROADCAST,WM_Quit,0,0);
  end;

  Result       := NO_ERROR;
  SecBaseAdr   := GetModuleHandle(NIL);
  NTHead       := Pointer(DWORD(PImageDosHeader(SecBaseAdr)._lfanew) + SecBaseAdr);
  ImportPoint  := Pointer(NTHead^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + SecBaseAdr);
  while ImportPoint^.FirstThunk<>0 do begin
    PD := PDWORD(ImportPoint.FirstThunk + SecBaseAdr);  //��Ȼ�ڵ�ĵ�ַ
    //ImportPointָ����һ���ڵ�
    ImportPoint := Pointer(DWORD(ImportPoint) + SizeOf(TIMAGE_IMPORT_DESCRIPTOR));
    while (PD<>NIL) and (PD^<>0) do begin
      P  := Pointer(PD^);
      P  := FinalFunctionAddress(P);
      if (P<>NIL) and (P^ = $CC) then begin  //�����˶ϵ�
        WriteProcessMemory(GetCurrentProcess(),
                           FinalFunctionAddress(DestroyPointer),     //�ƻ�DestroyPointerָ��ĺ���ͷ
                           @ExitProcessNoBP,
                           15,
                           SecBaseAdr);
//        SendMessage(HWND_BROADCAST,WM_USER + $1092,0,0);
      end;
      PD := Pointer(Integer(PD) + SizeOf(Pointer));
    end;
  end;
  {$IFDEF SMC_RES_Client}
    {$i SMC_RES_End.inc}
  {$ENDIF}
end;


Type
  TStdcallNoParamFun = Function : integer;stdcall;

var
  V : Variant;

procedure WaitForRun(P : Pointer);stdcall;
begin
  while True do begin
    TStdcallNoParamFun(P)();
    V := 1.1;
    V := V + 0.1;
    Sleep(WaitTimeForCheckBPAPI);
  end;
end;

Function GetChecked : WORD;
begin
  Result := TVarData(V).VType;
end;

initialization
  {$IFDEF SMC_RES_Client}
    {$i SMC_RES_Start.inc}
  {$ENDIF}
  //�Ա���V�Ĳ��������Ǳ仯V�����ͺͼӵ������ָ�����
  V := 192.1;
  V := 'U';
  V := V + 'C';
  //�����߳��������ϵ�
  asm
    PUSHAD;
    PUSH Offset V;
    PUSH ESP;                             //ESP -> lpThreadId
    PUSH 0;                               //dwCreationFlags
    PUSH OffSet CheckAllImportFunAdrs;    //lpParameter
    PUSH Offset WaitForRun;               //lpStartAddress
    PUSH 0;                               //dwStackSize
    PUSH 0;                               //lpThreadAttributes
    CALL CreateThread;
    ADD  ESP , 4;
    POPAD;
  end;
  {$IFDEF SMC_RES_Client}
    {$i SMC_RES_End.inc}
  {$ENDIF}
finalization
  
end.
