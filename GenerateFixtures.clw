  PROGRAM

  MAP
GenerateFixture PROCEDURE(STRING pName,STRING pOwner),LONG
GenerateFallbackFixture PROCEDURE(STRING pName),LONG
GenerateBatchFixture PROCEDURE(STRING pName),LONG
GenerateSuperfileFixture PROCEDURE(STRING pName),LONG
GenerateLargeRecordFixture PROCEDURE(STRING pName),LONG
PutLeShort      PROCEDURE(*STRING pData,LONG pOffset,LONG pValue)
PutLeLong       PROCEDURE(*STRING pData,LONG pOffset,LONG pValue)
PutBeLong       PROCEDURE(*STRING pData,LONG pOffset,LONG pValue)
  MODULE('kernel32.dll')
ExitProcess     PROCEDURE(ULONG pCode),PASCAL,RAW,NAME('ExitProcess'),DLL(1)
  END
  END

FixtureName     STRING(260)
FixtureOwner    STRING(100)
FallbackName    STRING(260)
LargeRawName    STRING(260)
BatchName       STRING(260)
SuperBaseName   STRING(260)
SuperDetailName STRING(260)
Result          LONG

  CODE
  Result = GenerateFixture('tests\fixtures\COMPREHENSIVE.TPS','')
  IF Result
    ExitProcess(Result)
  END
  Result = GenerateFixture('tests\fixtures\ENCRYPTED.TPS','sample-owner')
  IF Result
    ExitProcess(Result)
  END
  Result = GenerateFallbackFixture('tests\fixtures\UNNAMED.TPS')
  IF Result
    ExitProcess(Result)
  END
  Result = GenerateLargeRecordFixture('tests\fixtures\LARGE_RECORD.TPS')
  IF Result
    ExitProcess(Result)
  END
  Result = GenerateBatchFixture('tests\fixtures\BATCH10001.TPS')
  IF Result
    ExitProcess(Result)
  END
  Result = GenerateSuperfileFixture('tests\fixtures\SUPERFILE.TPS')
  IF Result
    ExitProcess(Result)
  END
  ExitProcess(0)

GenerateFixture PROCEDURE(STRING pName,STRING pOwner)
SampleFile      FILE,DRIVER('TOPSPEED'),NAME(FixtureName),OWNER(FixtureOwner),PRE(SMP),CREATE
ById              KEY(SMP:Id),PRIMARY
LargeMemo          MEMO(16384)
LargeBlob          BLOB,BINARY
Record             RECORD,PRE()
Id                   LONG
Moment               TIME
Amount               DECIMAL(12,2)
FixedText            STRING(8)
CStringText          CSTRING(8)
PStringText          PSTRING(8)
Numbers              LONG,DIM(2)
Mixed                GROUP
GroupText              STRING(4)
GroupNumber            LONG
GroupTail              STRING(2)
                     END
BigRecord            STRING(1000)
AliasA               STRING(4)
AliasB               STRING(4)
                   END
                 END
MemoData       &STRING
BlobData       &STRING
I              LONG
FileResult     LONG
  CODE
  MemoData &= NULL
  BlobData &= NULL
  FixtureName = pName
  FixtureOwner = pOwner
  REMOVE(SampleFile)
  CREATE(SampleFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  OPEN(SampleFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  MemoData &= NEW(STRING(12000))
  BlobData &= NEW(STRING(40000))
  LOOP I = 1 TO SIZE(MemoData)
    MemoData[I] = CHR(65 + (I % 26))
  END
  LOOP I = 1 TO SIZE(BlobData)
    BlobData[I] = CHR(I % 251)
  END

  CLEAR(SMP:Record)
  SMP:Id = 1
  SMP:Moment = (((11 * 60 * 60) + (7 * 60) + 13) * 100) + 42 + 1
  SMP:Amount = .12
  SMP:FixedText = 'AB'
  SMP:CStringText = 'CString'
  SMP:PStringText = 'Pascal'
  SMP:Numbers[1] = 11223344H
  SMP:Numbers[2] = 55667788H
  SMP:GroupText = 'G1'
  SMP:GroupNumber = 01020304H
  SMP:GroupTail[1] = CHR(0)
  SMP:GroupTail[2] = 'Z'
  SMP:BigRecord = 'X'
  SMP:AliasA = 'ONE'
  SMP:AliasB = 'TWO'
  SMP:LargeMemo = MemoData
  SMP:LargeBlob{PROP:Size} = SIZE(BlobData)
  SMP:LargeBlob[0 : SIZE(BlobData) - 1] = BlobData
  ADD(SampleFile)
  IF ERRORCODE()
    FileResult = ERRORCODE()
  END

  IF FileResult = 0
    CLEAR(SMP:Record)
    SMP:Id = 2
    SMP:Moment = 1
    SMP:Amount = 0
    SMP:FixedText = 'MIDNIGHT'
    SMP:CStringText = 'C2'
    SMP:PStringText = 'P2'
    SMP:GroupText = 'G2'
    SMP:GroupNumber = 0A0B0C0DH
    SMP:GroupTail = 'Q' & CHR(0)
    SMP:BigRecord = 'Y'
    SMP:AliasA = 'AAA'
    SMP:AliasB = 'BBB'
    SMP:LargeMemo = ''
    SMP:LargeBlob{PROP:Size} = 0
    SMP:LargeBlob{PROP:Touched} = TRUE
    ADD(SampleFile)
    IF ERRORCODE()
      FileResult = ERRORCODE()
    END
  END
  CLOSE(SampleFile)
  DISPOSE(MemoData)
  DISPOSE(BlobData)
  RETURN FileResult

GenerateFallbackFixture PROCEDURE(STRING pName)
FallbackFile    FILE,DRIVER('TOPSPEED'),NAME(FallbackName),PRE(UNNAMED),CREATE
SmallBlob         BLOB,BINARY
Record            RECORD,PRE()
Id                  LONG
Value               STRING(12)
                  END
                END
FallbackResult  LONG
  CODE
  FallbackName = pName
  REMOVE(FallbackFile)
  CREATE(FallbackFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  OPEN(FallbackFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(UNNAMED:Record)
  UNNAMED:Id = 1
  UNNAMED:Value = 'fallback'
  UNNAMED:SmallBlob{PROP:Size} = 2
  UNNAMED:SmallBlob[0] = CHR(0AAH)
  UNNAMED:SmallBlob[1] = CHR(055H)
  ADD(FallbackFile)
  FallbackResult = ERRORCODE()
  CLOSE(FallbackFile)
  RETURN FallbackResult

GenerateBatchFixture PROCEDURE(STRING pName)
BatchFile        FILE,DRIVER('TOPSPEED'),NAME(BatchName),PRE(BAT),CREATE
ById               KEY(BAT:Id),PRIMARY
Record             RECORD,PRE()
Id                   LONG
Value                STRING(16)
                   END
                 END
BatchResult      LONG
I                LONG
  CODE
  BatchName = pName
  REMOVE(BatchFile)
  CREATE(BatchFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  OPEN(BatchFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  STREAM(BatchFile)
  LOOP I = 1 TO 10001
    CLEAR(BAT:Record)
    BAT:Id = I
    BAT:Value = 'row ' & I
    ADD(BatchFile)
    IF ERRORCODE()
      BatchResult = ERRORCODE()
      BREAK
    END
  END
  FLUSH(BatchFile)
  IF ~BatchResult
    BatchResult = ERRORCODE()
  END
  CLOSE(BatchFile)
  RETURN BatchResult

GenerateSuperfileFixture PROCEDURE(STRING pName)
SuperBaseFile    FILE,DRIVER('TOPSPEED'),NAME(SuperBaseName),PRE(SBH),CREATE
ById               KEY(SBH:Id),PRIMARY
Record             RECORD,PRE()
Id                   LONG
Name                 STRING(20)
                   END
                 END
SuperDetailFile  FILE,DRIVER('TOPSPEED'),NAME(SuperDetailName),PRE(SDT),CREATE
ById               KEY(SDT:Id),PRIMARY
Record             RECORD,PRE()
Id                   LONG
ParentId             LONG
Text                 STRING(20)
                   END
                 END
SuperResult      LONG
  CODE
  SuperBaseName = pName
  SuperDetailName = CLIP(pName) & '\!DETAIL'
  REMOVE(SuperDetailFile)
  REMOVE(SuperBaseFile)
  CREATE(SuperBaseFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  OPEN(SuperBaseFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SBH:Record)
  SBH:Id = 1
  SBH:Name = 'base row'
  ADD(SuperBaseFile)
  SuperResult = ERRORCODE()
  CLOSE(SuperBaseFile)
  IF SuperResult
    RETURN SuperResult
  END
  CREATE(SuperDetailFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  OPEN(SuperDetailFile)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SDT:Record)
  SDT:Id = 10
  SDT:ParentId = 1
  SDT:Text = 'detail row'
  ADD(SuperDetailFile)
  SuperResult = ERRORCODE()
  CLOSE(SuperDetailFile)
  RETURN SuperResult

GenerateLargeRecordFixture PROCEDURE(STRING pName)
RawFile         FILE,DRIVER('DOS'),NAME(LargeRawName),PRE(LRG),CREATE
Record            RECORD
Byte                STRING(1)
                  END
                END
Raw             &STRING
I               LONG
Pos             LONG
LargeResult     LONG
  CODE
  Raw &= NEW(STRING(41216))
  LOOP I = 1 TO SIZE(Raw)
    Raw[I] = CHR(0)
  END
  LargeRawName = pName

  PutLeShort(Raw,4,512)
  Raw[15 : 18] = 'tOpS'
  PutLeLong(Raw,020H,0)
  PutLeLong(Raw,110H,159)

  PutLeLong(Raw,512,512)
  PutLeShort(Raw,516,108)
  PutLeShort(Raw,518,108)
  PutLeShort(Raw,522,1)
  Raw[525 + 1] = CHR(0C0H)
  PutLeShort(Raw,526,90)
  PutLeShort(Raw,528,7)
  PutBeLong(Raw,530,1)
  Raw[534 + 1] = CHR(0FAH)
  PutLeShort(Raw,535,0)
  Pos = 537
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,40000); Pos += 2
  PutLeShort(Raw,Pos,3); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  Raw[Pos + 1] = CHR(012H); Pos += 1
  PutLeShort(Raw,Pos,0); Pos += 2
  Raw[Pos + 1 : Pos + 11] = 'BIG:PAYLOAD'; Pos += 11
  Raw[Pos + 1] = CHR(0); Pos += 1
  PutLeShort(Raw,Pos,1); Pos += 2
  PutLeShort(Raw,Pos,40000); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  Raw[Pos + 1] = CHR(0); Pos += 1
  Raw[Pos + 1] = CHR(0); Pos += 1
  Raw[Pos + 1] = CHR(012H); Pos += 1
  PutLeShort(Raw,Pos,40000); Pos += 2
  Raw[Pos + 1 : Pos + 7] = 'A:VALUE'; Pos += 7
  Raw[Pos + 1] = CHR(0); Pos += 1
  PutLeShort(Raw,Pos,1); Pos += 2
  PutLeShort(Raw,Pos,4); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  Raw[Pos + 1] = CHR(0); Pos += 1
  Raw[Pos + 1] = CHR(0); Pos += 1
  Raw[Pos + 1] = CHR(012H); Pos += 1
  PutLeShort(Raw,Pos,40004); Pos += 2
  Raw[Pos + 1 : Pos + 7] = 'B:VALUE'; Pos += 7
  Raw[Pos + 1] = CHR(0); Pos += 1
  PutLeShort(Raw,Pos,1); Pos += 2
  PutLeShort(Raw,Pos,4); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  PutLeShort(Raw,Pos,0); Pos += 2
  Raw[Pos + 1] = CHR(0); Pos += 1
  Raw[Pos + 1] = CHR(0)

  PutLeLong(Raw,1024,1024)
  PutLeShort(Raw,1028,40035)
  PutLeShort(Raw,1030,40035)
  PutLeShort(Raw,1034,1)
  Raw[1037 + 1] = CHR(0C0H)
  PutLeShort(Raw,1038,40017)
  PutLeShort(Raw,1040,9)
  PutBeLong(Raw,1042,1)
  Raw[1046 + 1] = CHR(0F3H)
  PutBeLong(Raw,1047,1)
  Raw[1051 + 1 : 1051 + 40000] = ALL(' ',40000)
  Raw[1051 + 1] = 'L'
  Raw[1051 + 20000] = CHR(0)
  Raw[1051 + 40000] = 'Z'
  Raw[1051 + 40001 : 1051 + 40004] = 'ONE '
  Raw[1051 + 40005 : 1051 + 40008] = 'TWO '

  REMOVE(RawFile)
  CREATE(RawFile)
  IF ERRORCODE()
    DISPOSE(Raw)
    RETURN ERRORCODE()
  END
  OPEN(RawFile)
  IF ERRORCODE()
    DISPOSE(Raw)
    RETURN ERRORCODE()
  END
  LOOP I = 1 TO SIZE(Raw)
    LRG:Byte = Raw[I]
    ADD(RawFile)
    IF ERRORCODE()
      LargeResult = ERRORCODE()
      BREAK
    END
  END
  CLOSE(RawFile)
  DISPOSE(Raw)
  RETURN LargeResult

PutLeShort PROCEDURE(*STRING pData,LONG pOffset,LONG pValue)
  CODE
  pData[pOffset + 1] = CHR(BAND(pValue,0FFH))
  pData[pOffset + 2] = CHR(BAND(BSHIFT(pValue,-8),0FFH))

PutLeLong PROCEDURE(*STRING pData,LONG pOffset,LONG pValue)
  CODE
  pData[pOffset + 1] = CHR(BAND(pValue,0FFH))
  pData[pOffset + 2] = CHR(BAND(BSHIFT(pValue,-8),0FFH))
  pData[pOffset + 3] = CHR(BAND(BSHIFT(pValue,-16),0FFH))
  pData[pOffset + 4] = CHR(BAND(BSHIFT(pValue,-24),0FFH))

PutBeLong PROCEDURE(*STRING pData,LONG pOffset,LONG pValue)
  CODE
  pData[pOffset + 1] = CHR(BAND(BSHIFT(pValue,-24),0FFH))
  pData[pOffset + 2] = CHR(BAND(BSHIFT(pValue,-16),0FFH))
  pData[pOffset + 3] = CHR(BAND(BSHIFT(pValue,-8),0FFH))
  pData[pOffset + 4] = CHR(BAND(pValue,0FFH))
