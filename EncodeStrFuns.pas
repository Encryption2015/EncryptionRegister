unit EncodeStrFuns;

interface

uses
  SysUtils , Windows;

const
  BaseTable:string='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  Chrs : array[0..52] of char =
     (' ','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
      'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z');
  Numbers : array[0..9] of char =
     ('0','1','2','3','4','5','6','7','8','9');
  FuHaos : array[0..31] of char =
     (' ','!','@','#','$','%','^','&','*','(',')','-','_','=','+',       //1-14
      '[','{',']','}','\','|',';',':','"',',','<','.','>','/','?','`','~');


Function ELSString(S : String) : LongWord;
      
//Base64变码函数
function DecodeBase64(Source:string):string;
function EncodeBase64(Source:string):string;

//改变后的MD5
Function Encode_16Byte(sMessage : String) : String;
Function Encode_32Byte(sMessage : String) : String;


Function Space(n:integer):String;

//自定义加密过程
Function StrSNEncrypt(Str : string) : string;

//结果为Base64格式
Function StrEncodeBase(Source , Password : String):String;
Function StrDecodeBase(Source , Password : String):String;

//带密码的加密和解密算法 结果可能为乱码
Function StrEncode(Source , Password : String):String;
Function StrDecode(Source , Password : String):String;

//指定了密码的加密过程
Function StrBlueEncode(pass : String) : String;
Function StrBlueDecode(pass : String) : String;

//标准DES加密算法
function DESEncryStr(Str, Key: String): String;
function DESDecryStr(Str, Key: String): String;
function DESEncryStrHex(Str, Key: String): String;
function DESDecryStrHex(StrHex, Key: String): String;


implementation

Const
  BITS_TO_A_BYTE = 8;
  BYTES_TO_A_WORD = 4;
  BITS_TO_A_WORD = 32;
  m_lOnBits : array [0..30] of Uint =(1,3,7,15,31,63,127,255,511,1023,2047,
      4095,8191,16383,32767,65535,131071,262143,524287,1048575,2097151,4194303,
      8388607,16777215,33554431,67108863,134217727,268435455,536870911,1073741823,
      2147483647);

  m_l2Power : array [0..30] of Uint =(1,2,4,8,16,32,64,128,256,512,1024,2048,
      4096,8192,16384,32768,65536,131072,262144,524288,1048576,2097152,4194304,
      8388608,16777216,33554432,67108864,134217728,268435456,536870912,1073741824);

  S11 = 7;
  S12 = 12;
  S13 = 17;
  S14 = 22;
  S21 = 5;
  S22 = 9;
  S23 = 14;
  S24 = 20;
  S31 = 4;
  S32 = 11;
  S33 = 16;
  S34 = 23;
  S41 = 6;
  S42 = 10;
  S43 = 15;
  S44 = 21;
var
  lWordArray : array of Uint;

Function ELSString(S : String) : LongWord;
var
  g, h, i: LongWord;
begin
  h := 0;
  for i:=1 to Length(s) do begin
    h := h shl 4 + Ord(s[i]);
    g := h and $f0000000;
    if g <> 0 then
    h := h xor (g shr 24);
    h := h and (not g);
  end;
  Result := H;
end;

Function EncodeEncy(SMessage:String ; Byte16 : Boolean = True) : String;
  Function LShift(lValue, iShiftBits : Uint) : Uint;
  begin
    If iShiftBits = 0 Then
      begin
        LShift := lValue;
        Exit;
      end
    Else If iShiftBits = 31 Then begin
      If (lValue And 1)<>0 Then
        Result := $80000000
      else Result := 0;
      Exit;
    end;
    
    If (lValue And m_l2Power[31 - iShiftBits])<>0 Then
        Result := ((lValue And m_lOnBits[31 - (iShiftBits + 1)]) * m_l2Power[iShiftBits]) Or $80000000
    Else begin
      Result := ((lValue And m_lOnBits[31 - iShiftBits]) * m_l2Power[iShiftBits]);
    end;
  End;

  Function RShift(lValue, iShiftBits : Uint) : Uint;
  begin
    If iShiftBits = 0 Then
      begin
        RShift := lValue;
        Exit;
      end
    Else If iShiftBits = 31 Then
      begin
        If (lValue And $80000000)<>0 Then
          RShift := 1
        Else
          RShift := 0;
        Exit;
      end;
   
    RShift := (lValue And $7FFFFFFE) div m_l2Power[iShiftBits];

    If (lValue And $80000000)<>0 Then
      Result := (Result Or ($40000000 div m_l2Power[iShiftBits - 1]));
  End;

  Function RotateLeft(lValue, iShiftBits:Uint) : Uint;
  begin
    Result := LShift(lValue, iShiftBits) Or RShift(lValue, (32 - iShiftBits))
  End;

  Function AddUnsigned(lX, lY : Uint) : Uint;
  var
    lX8 , lY8 ,lX4 , lY4 ,lResult: Uint;
  begin
      lX8 := lX And $80000000;
      lY8 := lY And $80000000;
      lX4 := lX And $40000000;
      lY4 := lY And $40000000;
 
      lResult := (lX And $3FFFFFFF) + (lY And $3FFFFFFF);
 
      If (lX4 And lY4)<>0 Then
          lResult := lResult Xor $80000000 Xor lX8 Xor lY8
      Else If (lX4 Or lY4)<>0 Then
        begin
          If (lResult And $40000000)<>0 Then
              lResult := lResult Xor $C0000000 Xor lX8 Xor lY8
          Else
              lResult := lResult Xor $40000000 Xor lX8 Xor lY8
        end
      Else
          lResult := lResult Xor lX8 Xor lY8;
      Result := lResult;
  End;


  Procedure ConvertToWordArray(SMessage : String);
  Const
    MODULUS_BITS = 512;
    CONGRUENT_BITS = 448;
  var
    lMessageLength , lNumberOfWords , lBytePosition , lByteCount: Uint;
    lWordCount : Uint;
  begin
    lMessageLength := Length(sMessage);
    lNumberOfWords := (((lMessageLength + ((MODULUS_BITS - CONGRUENT_BITS) div BITS_TO_A_BYTE)) div (MODULUS_BITS div BITS_TO_A_BYTE)) + 1) * (MODULUS_BITS div BITS_TO_A_WORD);
    Setlength(lWordArray,lNumberOfWords);
    lByteCount := 0;
    while lByteCount <= lMessageLength do begin
      lWordCount := lByteCount div BYTES_TO_A_WORD ;
      lBytePosition := (lByteCount Mod BYTES_TO_A_WORD) * BITS_TO_A_BYTE;
      lWordArray[lWordCount] := lWordArray[lWordCount] Or LShift(ord(sMessage[lByteCount + 1]), lBytePosition);
      lByteCount := lByteCount + 1
   end;
   Dec(lByteCount);
   lWordCount := lByteCount div BYTES_TO_A_WORD;
   lBytePosition := (lByteCount Mod BYTES_TO_A_WORD) * BITS_TO_A_BYTE;
   lWordArray[lWordCount] := lWordArray[lWordCount] Or LShift($80, lBytePosition);
   lWordArray[lNumberOfWords - 2] := LShift(lMessageLength, 3);
   lWordArray[lNumberOfWords - 1] := RShift(lMessageLength, 29);
  end;

  Function Encode_F(x, y, z:Uint):Uint;
  begin
    Result := (x And y) Or ((Not x) And z);
  End;
  Function Encode_G(x, y, z:Uint):Uint;
  begin
    Result := (x And z) Or (y And (Not z));
  End;
  Function Encode_H(x, y, z:Uint):Uint;
  begin
    Encode_H := (x Xor y Xor z);
  End;

  Function Encode_I(x, y, z:Uint):Uint;
  begin
    Encode_I := (y Xor (x Or (Not z)));
  End;


  Procedure Encode_FF(var a, b, c, d:Uint; x:Uint; s, ac:Uint);
  begin
    a := AddUnsigned(a, AddUnsigned(AddUnsigned(Encode_F(b, c, d), x), ac));
    a := RotateLeft(a, s);
    a := AddUnsigned(a, b);
  End;


  Procedure Encode_GG(var a, b, c, d:Uint; x:Uint; s, ac:Uint);
  begin
      a := AddUnsigned(a, AddUnsigned(AddUnsigned(Encode_G(b, c, d), Cardinal(x)), ac));
      a := RotateLeft(a, s);
      a := AddUnsigned(a, b);
  End;

  Procedure Encode_HH(var a, b, c, d:Uint; x:Uint; s, ac:Uint);
  begin
      a := AddUnsigned(a, AddUnsigned(AddUnsigned(Encode_H(b, c, d), Cardinal(x)), ac));
      a := RotateLeft(a, s);
      a := AddUnsigned(a, b);
  End;

  Procedure Encode_II(var a, b, c, d:Uint; x:Uint; s, ac:Uint);
  begin
      a := AddUnsigned(a, AddUnsigned(AddUnsigned(Encode_I(b, c, d), Cardinal(x)), ac));
      a := RotateLeft(a, s);
      a := AddUnsigned(a, b);
  End;

  Function WordToHex(lValue:Uint) : String;
  var
   lCount , lByte: Uint;
   S : String;
  begin
    Result := '';
    For lCount := 0 To 3 do begin
     lByte := RShift(lValue, lCount * BITS_TO_A_BYTE) And m_lOnBits[BITS_TO_A_BYTE - 1];
     S := inttoHex(lByte,5);
     Result := Result + Copy(S,Length(S)-1,2);
    end
  End;



var
  a,b,c,d : Uint;
  AA,BB,CC,DD : Uint;
  K : integer;
begin
  Setlength(lWordArray,0);
  ConvertToWordArray(sMessage);
  a := $67452301;
  b := $EFCDAB89;
  c := $98BADCFE;
  d := $10325476;
  k := 0;
  while k<Length(lWordArray) do begin
    AA := a;
    BB := b;
    CC := c;
    DD := d;
    Encode_FF( a, b, c, d, lWordArray[k + 0], S11, $D76AA478);  //Add
    Encode_FF( a, b, c, d, lWordArray[k + 0], S11, $D76AA478);
    Encode_FF( d, a, b, c, lWordArray[k + 1], S12, $E8C7B756);
    Encode_FF( c, d, a, b, lWordArray[k + 2], S13, $242070D0);  //Last B-0
    Encode_FF( b, c, d, a, lWordArray[k + 3], S14, $C1BDCEEE);
    Encode_FF( a, b, c, d, lWordArray[k + 4], S11, $F57C0FAF);
    Encode_FF( d, a, b, c, lWordArray[k + 5], S12, $4787C62A);
    Encode_FF( d, a, b, c, lWordArray[k + 5], S12, $4787C62A);  //Add
    Encode_FF( c, d, a, b, lWordArray[k + 6], S13, $A8304613);
    Encode_FF( b, c, d, a, lWordArray[k + 7], S14, $FD469501);
    Encode_FF( a, b, c, d, lWordArray[k + 8], S11, $698098D2);  //Last 8-2
    Encode_FF( d, a, b, c, lWordArray[k + 9], S12, $8B44F7AF);
    Encode_FF( c, d, a, b, lWordArray[k + 10], S13, $FFFF5BB1);
    Encode_FF( c, d, a, b, lWordArray[k + 10], S13, $FFFF5BB1);  //Add
    Encode_FF( b, c, d, a, lWordArray[k + 11], S14, $895CD7BE);
    Encode_FF( a, b, c, d, lWordArray[k + 12], S11, $6B901122);
    Encode_FF( d, a, b, c, lWordArray[k + 13], S12, $FD987193);
    Encode_FF( c, d, a, b, lWordArray[k + 14], S13, $A679438E);
    Encode_FF( c, d, a, b, lWordArray[k + 14], S13, $A679438E);  //Add
    Encode_FF( b, c, d, a, lWordArray[k + 15], S14, $49B40821);

    Encode_GG( a, b, c, d, lWordArray[k + 1], S21, $F61E2562);
//Del    Encode_GG( d, a, b, c, lWordArray[k + 6], S22, $C040B340);
    Encode_GG( c, d, a, b, lWordArray[k + 11], S23, $265E5A51);
    Encode_GG( b, c, d, a, lWordArray[k + 0], S24, $E9B6C7AA);
    Encode_GG( a, b, c, d, lWordArray[k + 5], S21, $D62F105D);
    Encode_GG( d, a, b, c, lWordArray[k + 10], S22, $2441453);
    Encode_GG( c, d, a, b, lWordArray[k + 15], S23, $D8A1E681);
    Encode_GG( b, c, d, a, lWordArray[k + 4], S24, $E7D3FBC8);
    Encode_GG( a, b, c, d, lWordArray[k + 9], S21, $21E1CDE6);
    Encode_GG( d, a, b, c, lWordArray[k + 14], S22, $C33707D6);
    Encode_GG( d, a, b, c, lWordArray[k + 14], S22, $C33707D6);  //Add
    Encode_GG( c, d, a, b, lWordArray[k + 3], S23, $F4D50D87);
    Encode_GG( b, c, d, a, lWordArray[k + 8], S24, $455A14ED);
    Encode_GG( a, b, c, d, lWordArray[k + 13], S21, $A9E3E905);
    Encode_GG( a, b, c, d, lWordArray[k + 13], S21, $A9E3E905);  //Add
    Encode_GG( d, a, b, c, lWordArray[k + 2], S22, $FCEFA3F8);
    Encode_GG( c, d, a, b, lWordArray[k + 7], S23, $676F02D9);
    Encode_GG( b, c, d, a, lWordArray[k + 12], S24, $8D2A4C8A);

    Encode_HH( a, b, c, d, lWordArray[k + 5], S31, $FFFA3942);
    Encode_HH( d, a, b, c, lWordArray[k + 8], S32, $8771F681);
    Encode_HH( c, d, a, b, lWordArray[k + 11], S33, $6D9D6122);
    Encode_HH( b, c, d, a, lWordArray[k + 14], S34, $FDE5380C);
    Encode_HH( a, b, c, d, lWordArray[k + 1], S31, $A4BEEA44);
//Del    Encode_HH( d, a, b, c, lWordArray[k + 4], S32, $4BDECFA9);
    Encode_HH( c, d, a, b, lWordArray[k + 7], S33, $F6BB4B60);
    Encode_HH( b, c, d, a, lWordArray[k + 10], S34, $BEBFBC70);
    Encode_HH( a, b, c, d, lWordArray[k + 13], S31, $289B7EC6);
    Encode_HH( d, a, b, c, lWordArray[k + 0], S32, $EAA127FA);
    Encode_HH( d, a, b, c, lWordArray[k + 0], S32, $EAA127FA);  //Add
    Encode_HH( c, d, a, b, lWordArray[k + 3], S33, $D4EF3085);
    Encode_HH( b, c, d, a, lWordArray[k + 6], S34, $4881D05);
    Encode_HH( a, b, c, d, lWordArray[k + 9], S31, $D9D4D039);
    Encode_HH( d, a, b, c, lWordArray[k + 12], S32, $E6DB99E5);
    Encode_HH( c, d, a, b, lWordArray[k + 15], S33, $1FA27CF8);
    Encode_HH( b, c, d, a, lWordArray[k + 2], S34, $C4AC5665);

    Encode_II( a, b, c, d, lWordArray[k + 0], S41, $F4292244);
    Encode_II( d, a, b, c, lWordArray[k + 7], S42, $432AFF97);
    Encode_II( c, d, a, b, lWordArray[k + 14], S43, $AB9423A7);
    Encode_II( b, c, d, a, lWordArray[k + 5], S44, $FC93A039);
    Encode_II( a, b, c, d, lWordArray[k + 12], S41, $655B59C3);
//Del    Encode_II( d, a, b, c, lWordArray[k + 3], S42, $8F0CCC92);
    Encode_II( c, d, a, b, lWordArray[k + 10], S43, $FFEFF47D);
    Encode_II( b, c, d, a, lWordArray[k + 1], S44, $85845DD1);
    Encode_II( a, b, c, d, lWordArray[k + 8], S41, $6FA87E4F);
    Encode_II( d, a, b, c, lWordArray[k + 15], S42, $FE2CE6E0);
    Encode_II( d, a, b, c, lWordArray[k + 15], S42, $FE2CE6E0);  //Add
    Encode_II( c, d, a, b, lWordArray[k + 6], S43, $A3014314);
    Encode_II( b, c, d, a, lWordArray[k + 13], S44, $4E0811A1);
    Encode_II( a, b, c, d, lWordArray[k + 4], S41, $F7537E82);
    Encode_II( d, a, b, c, lWordArray[k + 11], S42, $BD3AF235);
    Encode_II( d, a, b, c, lWordArray[k + 11], S42, $BD3AF235);  //Add
    Encode_II( c, d, a, b, lWordArray[k + 2], S43, $2AD7D2BB);
    Encode_II( b, c, d, a, lWordArray[k + 9], S44, $EB86D395);  //Last 1-5

    a := AddUnsigned(a, AA);
    b := AddUnsigned(b, BB);
    c := AddUnsigned(c, CC);
    d := AddUnsigned(d, DD);
    k := k + 16;
  end;
  if Byte16 then
    Result :=LowerCase(WordToHex(B) + WordToHex(C))
  else
    Result := LowerCase(WordToHex(a) + WordToHex(b) + WordToHex(c) +WordToHex(d));
End;

Function Encode_16Byte(sMessage : String) : String;
begin
  if sMessage='' then Exit;
  Result := EncodeEncy(sMessage);
End;

Function Encode_32Byte(sMessage : String) : String;
begin
  if sMessage='' then Exit;
  Result := EncodeEncy(sMessage,False);
End;

Function StrSNEncrypt(Str : string) : string;
var
   TmpStr , cStr , AllStr: string;
   i , m , n ,j: integer;
//   TmpPchar : pchar;
begin
  AllStr := Str+'Ha啊1d1SrW29sh36+_<LP?>"756H的8R9q2ydS3hWy稿8Jiw6KY可6去Y@和!K$&OS5tBW6O';
  M := 0;
  for i:=1 to 50 do
     M := M + Ord(AllStr[i]);
  M := ( M mod 23) + 1;

  cStr     := Str+#0'H'#02'a1d1SrW29sh36+_<LP?>"756H'+AllStr;
  TmpStr   := Copy(cStr,M,4) + AllStr;

  cStr    := '';
  for i:=1 to 50 do begin
     n := Ord(TmpStr[i]) ;
     m := m + Ord(TmpStr[((n+470) mod 47)+1]);
     m := (m+290) mod 29;
     j := Ord(TmpStr[((n+340) mod 17)+1]);
     j := (j+380) mod 19;
     n := n+m-j;
     m := ((n+210) mod 7) + m-j;
     n := ((n+510) mod 255) + 1;
     cStr := cStr + chr(n);
  end;
  TmpStr := cStr;
  cStr := '';
  m := 0;
  for i:=1 to 50 do begin
     n := ord(TmpStr[i]) ;
     m := m +ord(TmpStr[((n+510) mod 51)+1]);
     m := (m+290) mod 29;
     j := ord(TmpStr[((n+170) mod 17)+1]);
     j := (j+190) mod 19;
     n := n+m-j;
     m := ((n+210) mod 7) + m-j;
     n := ((n+300) mod 90) + 32;
     cStr := Char(n) + cStr;
  end;
  Result := cStr;
end;

function FindInTable(CSource:char):integer;
begin
  result:=Pos(string(CSource),BaseTable)-1;
end;

function DecodeBase64(Source:string):string;
var
  SrcLen,Times,i:integer;
  x1,x2,x3,x4,xt:byte;
begin
  result:='';
  SrcLen:=Length(Source);
  Times:=SrcLen div 4;
  for i:=0 to Times-1 do
  begin
    x1:=FindInTable(Source[1+i*4]);
    x2:=FindInTable(Source[2+i*4]);
    x3:=FindInTable(Source[3+i*4]);
    x4:=FindInTable(Source[4+i*4]);
    x1:=x1 shl 2;
    xt:=x2 shr 4;
    x1:=x1 or xt;
    x2:=x2 shl 4;
    result:=result+chr(x1);
    if x3= 64 then break;
    xt:=x3 shr 2;
    x2:=x2 or xt;
    x3:=x3 shl 6;
    result:=result+chr(x2);
    if x4=64 then break;
    x3:=x3 or x4;
    result:=result+chr(x3);
  end;
end;

function EncodeBase64(Source:string):string;
var
  Times,LenSrc,i:integer;
  x1,x2,x3,x4:char;
  xt:byte;
begin
  result:='';
  LenSrc:=length(Source);
  if LenSrc mod 3 =0 then Times:=LenSrc div 3
  else Times:=LenSrc div 3 + 1;
  for i:=0 to times-1 do
  begin
    if LenSrc >= (3+i*3) then
    begin
      x1:=BaseTable[(ord(Source[1+i*3]) shr 2)+1];
      xt:=(ord(Source[1+i*3]) shl 4) and 48;
      xt:=xt or (ord(Source[2+i*3]) shr 4);
      x2:=BaseTable[xt+1];
      xt:=(Ord(Source[2+i*3]) shl 2) and 60;
      xt:=xt or (ord(Source[3+i*3]) shr 6);
      x3:=BaseTable[xt+1];
      xt:=(ord(Source[3+i*3]) and 63);
      x4:=BaseTable[xt+1];
    end
    else if LenSrc>=(2+i*3) then
    begin
      x1:=BaseTable[(ord(Source[1+i*3]) shr 2)+1];
      xt:=(ord(Source[1+i*3]) shl 4) and 48;
      xt:=xt or (ord(Source[2+i*3]) shr 4);
      x2:=BaseTable[xt+1];
      xt:=(ord(Source[2+i*3]) shl 2) and 60;
      x3:=BaseTable[xt+1];
      x4:='=';
    end else
    begin
      x1:=BaseTable[(ord(Source[1+i*3]) shr 2)+1];
      xt:=(ord(Source[1+i*3]) shl 4) and 48;
      x2:=BaseTable[xt+1];
      x3:='=';
      x4:='=';
    end;
    result:=result+x1+x2+x3+x4;
  end;
end;

Function StrEncodeBase(Source , Password : String):String;
var
  Tmp : String;
begin
  Tmp := StrEncode(Source,Password);
  Result := EncodeBase64(Tmp);
end;

Function StrDecodeBase(Source , Password : String):String;
var
  Tmp : String;
begin
  Tmp := DecodeBase64(Source);
  Result := StrDecode(Tmp,Password);
end;


Function StrEncode(Source , Password : String):String;
var
  i , Len , n , m , nTmp: integer;
  S : string;
  QPWD , HPWD : array [0..9] of Byte;
begin
  Result := '';
  if Source='' then exit;
  S := Copy(StrSNEncrypt(Password),1,20);
  Len := Length(Source);
  CopyMemory(@QPWD,@S[1],10);
  CopyMemory(@HPWD,@S[11],10);
  for i:=1 to Len do begin
    m := 13 * ( (QPWD[(i+Len) mod 10]*HPWD[i mod 10] + $59) mod $37);
    n := 11 * ( (HPWD[(i+Len) mod 10]*QPWD[i mod 10] + $90) mod $21);
    nTmp := (n + m + Ord(Source[i]));
    nTmp := nTmp and $FF;
    Result := Result + Char(nTmp);
  end;
end;

Function StrDecode(Source , Password : String):String;
var
  i , Len , n , m , nTmp: integer;
  S : string;
  QPWD , HPWD : array [0..9] of Byte;
begin
  Result := '';
  if Source='' then exit;
  S := Copy(StrSNEncrypt(Password),1,20);
  Len := Length(Source);
  CopyMemory(@Qpwd,@S[1],10);
  CopyMemory(@HPWD,@S[11],10);
  for i:=1 to Len do begin
    m := 13 * ( (QPWD[(i+Len) mod 10]*HPWD[i mod 10] + $59) mod $37);
    n := 11 * ( (HPWD[(i+Len) mod 10]*QPWD[i mod 10] + $90) mod $21);
    nTmp := Ord(Source[i]) - n - m + $FF00;
    nTmp := nTmp and $FF;
    Result := Result + Char(nTmp);
  end;
end;

Function Space(n:integer):String;
var
  i : integer;
begin
  Result := '';
  for i:=1 to n do Result := Result + ' ';
end;

Function StrBlueEncode(pass : String) : String;
var
  enpass , Tmp : String;
begin
  if Pass='' then Exit;
  enpass := Chrs[41]+Chrs[2]+Chrs[10]+Chrs[5]+Chrs[3]+Chrs[20]+Chrs[32]+Chrs[15]+Chrs[18]+Chrs[52]+Numbers[1]+FuHaos[26]+Numbers[0]+FuHaos[1];
  Tmp := StrEncode(pass,enpass);
  Result := EncodeBase64(Tmp);
end;

Function StrBlueDecode(pass : String) : String;
var
  enpass , Tmp : String;
begin
  if Pass='' then Exit;
  enpass := Chrs[41]+Chrs[2]+Chrs[10]+Chrs[5]+Chrs[3]+Chrs[20]+Chrs[32]+Chrs[15]+Chrs[18]+Chrs[52]+Numbers[1]+FuHaos[26]+Numbers[0]+FuHaos[1];
  Tmp := DecodeBase64(pass);
  Result := StrDecode(Tmp,enpass);
end;



type
  TKeyByte = array[0..5] of Byte;
  TDesMode = (dmEncry, dmDecry);


var
  subKey: array[0..15] of TKeyByte;  
  
const
  BitIP: array[0..63] of Byte =   //初始值置IP
    (57, 49, 41, 33, 25, 17,  9,  1,
     59, 51, 43, 35, 27, 19, 11,  3,
     61, 53, 45, 37, 29, 21, 13,  5,
     63, 55, 47, 39, 31, 23, 15,  7,
     56, 48, 40, 32, 24, 16,  8,  0,
     58, 50, 42, 34, 26, 18, 10,  2,
     60, 52, 44, 36, 28, 20, 12,  4,
     62, 54, 46, 38, 30, 22, 14,  6 );

  BitCP: array[0..63] of Byte = //逆初始置IP-1
    ( 39,  7, 47, 15, 55, 23, 63, 31,
      38,  6, 46, 14, 54, 22, 62, 30,
      37,  5, 45, 13, 53, 21, 61, 29,
      36,  4, 44, 12, 52, 20, 60, 28,
      35,  3, 43, 11, 51, 19, 59, 27,
      34,  2, 42, 10, 50, 18, 58, 26,
      33,  1, 41,  9, 49, 17, 57, 25,
      32,  0, 40,  8, 48, 16, 56, 24 );

  BitExp: array[0..47] of Integer = // 位选择函数E
    ( 31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9,10,
      11,12,11,12,13,14,15,16,15,16,17,18,19,20,19,20,
      21,22,23,24,23,24,25,26,27,28,27,28,29,30,31,0  );

  BitPM: array[0..31] of Byte =  //置换函数P
    ( 15, 6,19,20,28,11,27,16, 0,14,22,25, 4,17,30, 9,
       1, 7,23,13,31,26, 2, 8,18,12,29, 5,21,10, 3,24 );

  sBox: array[0..7] of array[0..63] of Byte =    //S盒
    ( ( 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 ),

      ( 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 ),

      ( 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 ),

      (  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 ),

      (  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 ),

      ( 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 ),

      (  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 ),

      ( 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 ) );

  BitPMC1: array[0..55] of Byte = //选择置换PC-1
    ( 56, 48, 40, 32, 24, 16,  8,
       0, 57, 49, 41, 33, 25, 17,
       9,  1, 58, 50, 42, 34, 26,
      18, 10,  2, 59, 51, 43, 35,
      62, 54, 46, 38, 30, 22, 14,
       6, 61, 53, 45, 37, 29, 21,
      13,  5, 60, 52, 44, 36, 28,
      20, 12,  4, 27, 19, 11,  3 );

  BitPMC2: array[0..47] of Byte =//选择置换PC-2 
    ( 13, 16, 10, 23,  0,  4,
       2, 27, 14,  5, 20,  9,
      22, 18, 11,  3, 25,  7,
      15,  6, 26, 19, 12,  1,
      40, 51, 30, 36, 46, 54,
      29, 39, 50, 44, 32, 47,
      43, 48, 38, 55, 33, 52,
      45, 41, 49, 35, 28, 31 );

procedure initPermutation(var inData: array of Byte);
var
  newData: array[0..7] of Byte;
  i: Integer;
begin
  FillChar(newData, 8, 0);
  for i := 0 to 63 do
    if (inData[BitIP[i] shr 3] and (1 shl (7- (BitIP[i] and $07)))) <> 0 then
      newData[i shr 3] := newData[i shr 3] or (1 shl (7-(i and $07)));
  for i := 0 to 7 do inData[i] := newData[i];
end;

procedure conversePermutation(var inData: array of Byte);
var
  newData: array[0..7] of Byte;
  i: Integer;
begin
  FillChar(newData, 8, 0);
  for i := 0 to 63 do
    if (inData[BitCP[i] shr 3] and (1 shl (7-(BitCP[i] and $07)))) <> 0 then
      newData[i shr 3] := newData[i shr 3] or (1 shl (7-(i and $07)));
  for i := 0 to 7 do inData[i] := newData[i];
end;

procedure expand(inData: array of Byte; var outData: array of Byte);
var
  i: Integer;
begin
  FillChar(outData, 6, 0);
  for i := 0 to 47 do
    if (inData[BitExp[i] shr 3] and (1 shl (7-(BitExp[i] and $07)))) <> 0 then
      outData[i shr 3] := outData[i shr 3] or (1 shl (7-(i and $07)));
end;

procedure permutation(var inData: array of Byte);
var
  newData: array[0..3] of Byte;
  i: Integer;
begin
  FillChar(newData, 4, 0);
  for i := 0 to 31 do
    if (inData[BitPM[i] shr 3] and (1 shl (7-(BitPM[i] and $07)))) <> 0 then
      newData[i shr 3] := newData[i shr 3] or (1 shl (7-(i and $07)));
  for i := 0 to 3 do inData[i] := newData[i];
end;

function si(s,inByte: Byte): Byte;
var
  c: Byte;
begin
  c := (inByte and $20) or ((inByte and $1e) shr 1) or
    ((inByte and $01) shl 4);
  Result := (sBox[s][c] and $0f);
end;

procedure permutationChoose1(inData: array of Byte;
  var outData: array of Byte);
var
  i: Integer;
begin
  FillChar(outData, 7, 0);
  for i := 0 to 55 do
    if (inData[BitPMC1[i] shr 3] and (1 shl (7-(BitPMC1[i] and $07)))) <> 0 then
      outData[i shr 3] := outData[i shr 3] or (1 shl (7-(i and $07)));
end;

procedure permutationChoose2(inData: array of Byte;
  var outData: array of Byte);
var
  i: Integer;
begin
  FillChar(outData, 6, 0);
  for i := 0 to 47 do
    if (inData[BitPMC2[i] shr 3] and (1 shl (7-(BitPMC2[i] and $07)))) <> 0 then
      outData[i shr 3] := outData[i shr 3] or (1 shl (7-(i and $07)));
end;

procedure cycleMove(var inData: array of Byte; bitMove: Byte);
var
  i: Integer;
begin
  for i := 0 to bitMove - 1 do
  begin
    inData[0] := (inData[0] shl 1) or (inData[1] shr 7);
    inData[1] := (inData[1] shl 1) or (inData[2] shr 7);
    inData[2] := (inData[2] shl 1) or (inData[3] shr 7);
    inData[3] := (inData[3] shl 1) or ((inData[0] and $10) shr 4);
    inData[0] := (inData[0] and $0f);
  end;
end;

procedure makeKey(inKey: array of Byte; var outKey: array of TKeyByte);
const
  bitDisplace: array[0..15] of Byte =
    ( 1,1,2,2, 2,2,2,2, 1,2,2,2, 2,2,2,1 );
var
  outData56: array[0..6] of Byte;
  key28l: array[0..3] of Byte;
  key28r: array[0..3] of Byte;
  key56o: array[0..6] of Byte;
  i: Integer;
begin
  permutationChoose1(inKey, outData56);

  key28l[0] := outData56[0] shr 4;
  key28l[1] := (outData56[0] shl 4) or (outData56[1] shr 4);
  key28l[2] := (outData56[1] shl 4) or (outData56[2] shr 4);
  key28l[3] := (outData56[2] shl 4) or (outData56[3] shr 4);
  key28r[0] := outData56[3] and $0f;
  key28r[1] := outData56[4];
  key28r[2] := outData56[5];
  key28r[3] := outData56[6];

  for i := 0 to 15 do
  begin
    cycleMove(key28l, bitDisplace[i]);
    cycleMove(key28r, bitDisplace[i]);
    key56o[0] := (key28l[0] shl 4) or (key28l[1] shr 4);
    key56o[1] := (key28l[1] shl 4) or (key28l[2] shr 4);
    key56o[2] := (key28l[2] shl 4) or (key28l[3] shr 4);
    key56o[3] := (key28l[3] shl 4) or (key28r[0]);
    key56o[4] := key28r[1];
    key56o[5] := key28r[2];
    key56o[6] := key28r[3];
    permutationChoose2(key56o, outKey[i]);
  end;
end;

procedure encry(inData, subKey: array of Byte;
   var outData: array of Byte);
var
  outBuf: array[0..5] of Byte;
  buf: array[0..7] of Byte;
  i: Integer;
begin
  expand(inData, outBuf);
  for i := 0 to 5 do outBuf[i] := outBuf[i] xor subKey[i];
  buf[0] := outBuf[0] shr 2;
  buf[1] := ((outBuf[0] and $03) shl 4) or (outBuf[1] shr 4);
  buf[2] := ((outBuf[1] and $0f) shl 2) or (outBuf[2] shr 6);
  buf[3] := outBuf[2] and $3f;
  buf[4] := outBuf[3] shr 2;
  buf[5] := ((outBuf[3] and $03) shl 4) or (outBuf[4] shr 4);
  buf[6] := ((outBuf[4] and $0f) shl 2) or (outBuf[5] shr 6);
  buf[7] := outBuf[5] and $3f;                                
  for i := 0 to 7 do buf[i] := si(i, buf[i]);
  for i := 0 to 3 do outBuf[i] := (buf[i*2] shl 4) or buf[i*2+1];
  permutation(outBuf);
  for i := 0 to 3 do outData[i] := outBuf[i];
end;

procedure desData(desMode: TDesMode;
  inData: array of Byte; var outData: array of Byte);
// inData, outData 都为8Bytes，否则出错
var
  i, j: Integer;
  temp, buf: array[0..3] of Byte;
begin
  for i := 0 to 7 do outData[i] := inData[i];
  initPermutation(outData);
  if desMode = dmEncry then
  begin
    for i := 0 to 15 do
    begin
      for j := 0 to 3 do temp[j] := outData[j];                 //temp = Ln
      for j := 0 to 3 do outData[j] := outData[j + 4];	        //Ln+1 = Rn
      encry(outData, subKey[i], buf);                           //Rn ==Kn==> buf
      for j := 0 to 3 do outData[j + 4] := temp[j] xor buf[j];  //Rn+1 = Ln^buf
    end;

    for j := 0 to 3 do temp[j] := outData[j + 4];
    for j := 0 to 3 do outData[j + 4] := outData[j];
    for j := 0 to 3 do outData[j] := temp[j];
  end
  else if desMode = dmDecry then
  begin
    for i := 15 downto 0 do
    begin
      for j := 0 to 3 do temp[j] := outData[j];
      for j := 0 to 3 do outData[j] := outData[j + 4];
      encry(outData, subKey[i], buf);
      for j := 0 to 3 do outData[j + 4] := temp[j] xor buf[j];
    end;
    for j := 0 to 3 do temp[j] := outData[j + 4];
    for j := 0 to 3 do outData[j + 4] := outData[j];
    for j := 0 to 3 do outData[j] := temp[j];
  end;
  conversePermutation(outData);
end;

//////////////////////////////////////////////////////////////

function DESEncryStr(Str, Key: String): String;
var
  StrByte, OutByte, KeyByte: array[0..7] of Byte;
  StrResult: String;
  I, J: Integer;
begin
  if (Length(Str) > 0) and (Ord(Str[Length(Str)]) = 0) then
    raise Exception.Create('Error: the last char is NULL char.');
  if Length(Key) < 8 then
    while Length(Key) < 8 do Key := Key + Chr(0);
  while Length(Str) mod 8 <> 0 do Str := Str + Chr(0);

  for J := 0 to 7 do KeyByte[J] := Ord(Key[J + 1]);
  makeKey(keyByte, subKey);

  StrResult := '';

  for I := 0 to Length(Str) div 8 - 1 do
  begin
    for J := 0 to 7 do
      StrByte[J] := Ord(Str[I * 8 + J + 1]);
    desData(dmEncry, StrByte, OutByte);
    for J := 0 to 7 do
      StrResult := StrResult + Chr(OutByte[J]);
  end;

  Result := StrResult;
end;

function DESDecryStr(Str, Key: String): String;
var
  StrByte, OutByte, KeyByte: array[0..7] of Byte;
  StrResult: String;
  I, J: Integer;
begin
  if Length(Key) < 8 then
    while Length(Key) < 8 do Key := Key + Chr(0);

  for J := 0 to 7 do KeyByte[J] := Ord(Key[J + 1]);
  makeKey(keyByte, subKey);

  StrResult := '';

  for I := 0 to Length(Str) div 8 - 1 do
  begin
    for J := 0 to 7 do StrByte[J] := Ord(Str[I * 8 + J + 1]);
    desData(dmDecry, StrByte, OutByte);
    for J := 0 to 7 do
      StrResult := StrResult + Chr(OutByte[J]);
  end;
  while (Length(StrResult) > 0) and
    (Ord(StrResult[Length(StrResult)]) = 0) do
    Delete(StrResult, Length(StrResult), 1);
  Result := StrResult;
end;

///////////////////////////////////////////////////////////

function DESEncryStrHex(Str, Key: String): String;
var
  StrResult, TempResult, Temp: String;
  I: Integer;
begin
  TempResult := DESEncryStr(Str, Key);
  StrResult := '';
  for I := 0 to Length(TempResult) - 1 do
  begin
    Temp := Format('%x', [Ord(TempResult[I + 1])]);
    if Length(Temp) = 1 then Temp := '0' + Temp;
    StrResult := StrResult + Temp;
  end;
  Result := StrResult;
end;

function DESDecryStrHex(StrHex, Key: String): String;
  function HexToInt(Hex: String): Integer;
  var
    I, Res: Integer;
    ch: Char;
  begin
    Res := 0;
    for I := 0 to Length(Hex) - 1 do
    begin
      ch := Hex[I + 1];
      if (ch >= '0') and (ch <= '9') then
        Res := Res * 16 + Ord(ch) - Ord('0')
      else if (ch >= 'A') and (ch <= 'F') then
        Res := Res * 16 + Ord(ch) - Ord('A') + 10
      else if (ch >= 'a') and (ch <= 'f') then
        Res := Res * 16 + Ord(ch) - Ord('a') + 10
      else raise Exception.Create('Error: not a Hex String');
    end;
    Result := Res;
  end;

var
  Str, Temp: String;
  I: Integer;
begin
  Str := '';
  for I := 0 to Length(StrHex) div 2 - 1 do
  begin
    Temp := Copy(StrHex, I * 2 + 1, 2);
    Str := Str + Chr(HexToInt(Temp));
  end;
  Result := DESDecryStr(Str, Key);
end;

end.
