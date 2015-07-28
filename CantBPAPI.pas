//***********************检查导入表函数是否被设置了中断***********************//
//Author : Dazzling Blue 蓝色光芒                                             //
//2006-2-28 last update at www.1284.net                                       //
//功能：检查程序的导入表函数是否被设置了断点(Ring 3断点)                      //
//      如果发现被设置了中断 将破坏由DestroyPointer指定的地址                 //
//新开线程进行检查，检查时间间隔由WaitTimeForCheckBPAPI指定                   //
//检查时不会主动调用这个DestroyPointer地址，所以应该设置一个频繁调用的API地址 //
//该方式Dump一样被检查在内                                                    //
//****************************************************************************//
unit CantBPAPI;

//如果没有SMC_RES_Client单元，请注释掉以下这行。SMC_RES_Client为代码自修改和还原
//{$Define SMC_RES_Client}

interface

Uses
  Windows , Messages
  {$IFDEF SMC_RES_Client}
  ,SMC_RES_Client
  {$ENDIF}
  ;

procedure CloseApplication;

//如果返回 varCurrency 说明已经检查过了
Function GetChecked : WORD;

implementation

Const
  //检查时间间隔
  WaitTimeForCheckBPAPI = 60 * 1000;  //60秒检查一次
  //破坏这个地址
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
  ADD  ESP , $100;                 //破坏ESP
  ADD  EBP , $100;                 //破坏EBP
  JMP  EAX;
end;

//检查所有导入表函数是否被设置了断点，并作出响应

Function CheckAllImportFunAdrs : integer;stdcall;
var
  SecBaseAdr  : DWORD;                     //基地址
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
    CloseApplication2;       //如果还是没有被关掉的话，那就只好广播一个消息了
    PostMessage(HWND_BROADCAST,WM_Quit,0,0);
  end;

  Result       := NO_ERROR;
  SecBaseAdr   := GetModuleHandle(NIL);
  NTHead       := Pointer(DWORD(PImageDosHeader(SecBaseAdr)._lfanew) + SecBaseAdr);
  ImportPoint  := Pointer(NTHead^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + SecBaseAdr);
  while ImportPoint^.FirstThunk<>0 do begin
    PD := PDWORD(ImportPoint.FirstThunk + SecBaseAdr);  //当然节点的地址
    //ImportPoint指向下一个节点
    ImportPoint := Pointer(DWORD(ImportPoint) + SizeOf(TIMAGE_IMPORT_DESCRIPTOR));
    while (PD<>NIL) and (PD^<>0) do begin
      P  := Pointer(PD^);
      P  := FinalFunctionAddress(P);
      if (P<>NIL) and (P^ = $CC) then begin  //发现了断点
        WriteProcessMemory(GetCurrentProcess(),
                           FinalFunctionAddress(DestroyPointer),     //破坏DestroyPointer指向的函数头
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
  //对变量V的操作仅仅是变化V的类型和加点点无用指令而已
  V := 192.1;
  V := 'U';
  V := V + 'C';
  //开新线程序间隔检查断点
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
