//下面几个函数是我早年破解的传奇3加密解密算法。当时是看着汇编改写的。函数挺乱的，一直没有去整理。函数支持3个字符以上的字符加密，呵呵挺好用的。我一直在用，这里也要谢谢传奇3小组提供的算法。
{ **********************************************************************************
       传奇3加密解密函数库
       Copyright (c) 1999-2004, ZSY
       All Right Reserved

       Author: zsy
       Date:   2003-9-28
********************************************************************************** }
unit zEcrypt;

interface
  uses Windows,Variants,SysUtils;

procedure Loginecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
procedure Logindecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
procedure Gamedecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
procedure Gameecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
function LoginecryptStr(Buf: pchar;Len: DWORD):string;
function LogindDec(Buf: pchar;Len: DWORD):string;

implementation

function LoginecryptStr(Buf: pchar;Len: DWORD):string;
var
  i,j,k: Integer;
  s1,s2,s3,s4: integer;
  i1,i2,i3,Ecx: integer;
begin
  i1 := 0;  //ebp-04
  i2 := 0;  //ebp-08
  i3 := 0;
  i := 0;
  while i < Len do
  begin
    i2 := i2 + 1;
    Ecx := 8;
    s1 := ord(buf[i]);
    i2 := i2 + 1;
    s2 := s1;
    s1 := (s1 shr i2) or $80000000;
    Ecx := Ecx - i2;
    s1 := s1 or i3;
    s2 := s2 shl Ecx;
    s1 := s1 and $3f;
    s1 := s1 + $3c;
    Result := Result + chr(s1);//vartostr(inttohex(s1,1))+' ';

    s2 := s2 shr 02;
    i3 := LoWord(s2) and $3f;
    i := i + 1;
    if i2 = 06 then
    begin
      i3 := i3 + $3c;
      i2 := 0;
      Result := Result + chr(i3);//vartostr(inttohex(i3,1))+' ';
      i3 := 0;
    end;
    i1 := i1 + 1;
    if i1 >= Len then
    begin
      if i2 <> 0 then
      begin
        i3 := i3 + $3c;
       Result := Result + chr(i3);
        break;
      end;
//      NewBuf := NewBuf + chr(ord(NewBuf[length(NewBuf)-1]) and 0);
      break;
    end;
  end;
end;

function LogindDec(Buf: pchar;Len: DWORD):string;
var
  i,j,k: Integer;
  s1,s2,s3,s4: integer;
  i1,i2,Ecx: integer;
begin
  i1 := 2;  //ebp-04
  i2 := 2;  //ebp-08
  i := 0;
  while i < Len do
  begin
    s1 := ord(buf[i]);
    if s1 >= $3c then
    begin
      Ecx := 6;
      s2 := ord(buf[i+1]);
      Ecx := Ecx - i1;
      s1 := s1 - $3c;
      s2 := s2 - $3c;
      if s2 < 0 then
        s2 := (s2 shr Ecx) and ($80000000)
      else
        s2 := (s2 shr Ecx);
      Ecx := i1;
      s1 := LoByte(s1 shl ecx);  //这里比较关键
      s4 := s1 + s2;
      Result := Result + chr(s4);//vartostr(inttohex(s4,1))+' ';
      i1 := i1 + 2;
      if i2 < Len then
      begin
        s3 := ord(buf[i+2]);
        if s3 >= $3c then
        begin
          //
        end;
      end;
      if i1 = 08 then
      begin
        i1 := 2;
        i := i + 1;
        i2 := i2 + 1;
      end;
      i2 := i2 + 1;
      i := i + 1;
    end
    else
      break;
  end;    // while
end;

procedure Loginecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
var
  i,j,k: Integer;
  s1,s2,s3,s4: integer;
  i1,i2,i3,Ecx: integer;
begin
  i1 := 0;  //ebp-04
  i2 := 0;  //ebp-08
  i3 := 0;
  i := 0;
  while i < Len do
  begin
    i2 := i2 + 1;
    Ecx := 8;
    s1 := ord(buf[i]);
    i2 := i2 + 1;
    s2 := s1;
    s1 := (s1 shr i2) or $80000000;
    Ecx := Ecx - i2;
    s1 := s1 or i3;
    s2 := s2 shl Ecx;
    s1 := s1 and $3f;
    s1 := s1 + $3c;
    NewBuf := NewBuf + chr(s1);//vartostr(inttohex(s1,1))+' ';

    s2 := s2 shr 02;
    i3 := LoWord(s2) and $3f;
    i := i + 1;
    if i2 = 06 then
    begin
      i3 := i3 + $3c;
      i2 := 0;
      NewBuf := NewBuf + chr(i3);//vartostr(inttohex(i3,1))+' ';
      i3 := 0;
    end;
    i1 := i1 + 1;
    if i1 >= Len then
    begin
      if i2 <> 0 then
      begin
        i3 := i3 + $3c;
        NewBuf := NewBuf + chr(i3);
        break;
      end;
//      NewBuf := NewBuf + chr(ord(NewBuf[length(NewBuf)-1]) and 0);
      break;
    end;
  end;
end;

procedure Logindecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
var
  i,j,k: Integer;
  s1,s2,s3,s4: integer;
  i1,i2,Ecx: integer;
begin
  i1 := 2;  //ebp-04
  i2 := 2;  //ebp-08
  i := 0;
  while i < Len do
  begin
    s1 := ord(buf[i]);
    if s1 >= $3c then
    begin
      Ecx := 6;
      s2 := ord(buf[i+1]);
      Ecx := Ecx - i1;
      s1 := s1 - $3c;
      s2 := s2 - $3c;
      if s2 < 0 then
        s2 := (s2 shr Ecx) and ($80000000)
      else
        s2 := (s2 shr Ecx);
      Ecx := i1;
      s1 := LoByte(s1 shl ecx);  //这里比较关键
      s4 := s1 + s2;
      NewBuf := NewBuf + chr(s4);//vartostr(inttohex(s4,1))+' ';
      i1 := i1 + 2;
      if i2 < Len then
      begin
        s3 := ord(buf[i+2]);
        if s3 >= $3c then
        begin
          //
        end;
      end;
      if i1 = 08 then
      begin
        i1 := 2;
        i := i + 1;
        i2 := i2 + 1;
      end;
      i2 := i2 + 1;
      i := i + 1;
    end
    else
      break;
  end;    // while
end;

procedure Gameecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
var
  i,i1,i2: Integer;
  t,t1,Edi,Eax,Ecx: integer;
begin
  i1 := 0;
  Edi := 0;
  Eax := 0;
  i := 0;
  while i < Len do
  begin
    i1 := i1 + 2;
    t := ord(Buf[i]);
    i2 := i1;
    t1 := t;
    t := t and $000000FF;
    t1 := t1 shr i1;
    i1 := 6;
    i1 := i1 - Edi;
    Edi := i2;
    t := t shl i1;
    t1 := t1 or Eax;
    t1 := t1 and $3F;
    t := t  shr $2;
    t := t and $3F;
    if Edi = 6 then
    begin
      Ecx := $2000-1;
      if i > Ecx then
      begin
      end;
      t1 := t1 + $3C;
      NewBuf := pchar(NewBuf + chr(t1));//vartostr(inttohex(t1,1))+' ');
      t := t + $3C;
      NewBuf := pchar(NewBuf + chr(t));//vartostr(inttohex(t,1))+' ');
      Edi := 0;
      i2 := 0;
      Eax := 0;
    end
    else begin
      Eax := t;
      t1 := t1 + $3c;
      newBuf := pchar(Newbuf + chr(t1));//vartostr(inttohex(t1,1))+' ');
    end;
    i := i + 1;
    i1 := i2;
  end;
  if edi = 0 then
    newBuf := pchar(Newbuf + chr($00))//vartostr(inttohex(t1,1))+' ');
  else begin
    Eax := Eax + $3C;
    newBuf := pchar(Newbuf + chr(Eax));//vartostr(inttohex(t1,1))+' ');
  end;
end;


procedure Gamedecrypt(Buf: pchar;Len: DWORD;var NewBuf: string);
var
  i,i1,i2: integer;
  t,t1,t2: integer;
  Eax,Edi,Ecx,Edx: integer;
  tmp: string;
begin
  i1 := 2;
  i := 0;
  Edx := 2;
  Edi := 0;
  eax := 0;
  ecx := 0;
  while i < Len do
  begin
    t := ord(buf[i]);
    t1 := t;
    t1 := t1 - $3C;
    t1 := t1 + Edi;
    t := t - $3C;
    Ecx := $2000;
    if i > Ecx then exit;
    Ecx := Edi+6;
    if Ecx >= 8 then
    begin
      Ecx := 6;
      i2 := t;
      Ecx := Ecx - Edx;
      i2 := i2 and $3F;
      i2 := i2 shr Ecx;
      ecx := ord(tmp[1]);
      Edi := 0;
      i2 := i2 or ecx;
      Newbuf := NewBuf + chr(i2);//vartostr(inttohex(i2,1))+' ';
      if edx = 6 then
      begin
        edx := 2;
        i := i +1;
        continue;
      end
      else
        edx := edx + 2;
    end;
    Ecx := Edx;
    t := t shl Ecx;
    ecx := t;
    Eax := 8;
    eax := eax - edx;
    tmp := chr(ecx);
    Edi := Edi + eax;
    i := i + 1;
  end;
end;

end.


{调用

Logindecrypt(pchar(msg),Length(msg),NewBuf);

希望对大家有帮助   }

