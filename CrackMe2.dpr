program CrackMe2;

uses
  Forms,
  UnitMain in 'UnitMain.pas' {FrmMain},
  untWaterEffect in 'untWaterEffect.pas',
  CantBPAPI in 'CantBPAPI.pas',
  zEcrypt in 'zEcrypt.pas',
  EncodeStrFuns in 'EncodeStrFuns.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFrmMain, FrmMain);
  Application.Run;
end.
