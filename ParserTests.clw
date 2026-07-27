  PROGRAM

  INCLUDE('TpsParser.inc'),ONCE

  MAP
RequireLong      PROCEDURE(LONG pActual,LONG pExpected,LONG pCode)
RequireString    PROCEDURE(STRING pActual,STRING pExpected,LONG pCode)
RequirePositive  PROCEDURE(LONG pActual,LONG pMinimum,LONG pCode)
RequireNonzero   PROCEDURE(LONG pActual,LONG pCode)
  MODULE('kernel32.dll')
ExitProcess      PROCEDURE(ULONG pCode),PASCAL,RAW,NAME('ExitProcess'),DLL(1)
  END
  END

RegressionTpsParserType CLASS(TpsParserType),TYPE
BlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength),STRING
SelectRawTableNumber PROCEDURE(LONG pTableNo),LONG
BuildFragmentedBlobFixture PROCEDURE,LONG
BuildInvalidMemoFixture PROCEDURE,LONG
                       END

MetadataProgressProbeType CLASS(TpsProgressSinkType),TYPE
SawDefinitions              BYTE
SawRecords                  BYTE
Update                      PROCEDURE(STRING pStage,LONG pCompleted,LONG pTotal),VIRTUAL,DERIVED
                          END

Parser           RegressionTpsParserType
MetadataProgress MetadataProgressProbeType
Result           LONG
I                LONG
ExpectedTime     LONG
GroupRaw         STRING(10)
GroupString      STRING(10)
ExpectedGroup    STRING(10)
MemoText         STRING(12000)
LargeRaw         STRING(40000)
BlobPreview      STRING(16)
BlobLength       LONG
FragmentedBlob   STRING(6)
TempBlobName     STRING(260)
CorruptFixtureRoot STRING(260)
CorruptCountPath STRING(260)
CorruptRlePath   STRING(260)
CorruptPagePath  STRING(260)
CorruptBlockRangePath STRING(260)
CorruptBlobPath  STRING(260)
CorruptBlobNegativePath STRING(260)
CorruptBlobMissingPath STRING(260)

BlobFile         FILE,DRIVER('TOPSPEED'),NAME(TempBlobName),PRE(BTF),CREATE
Payload            BLOB,BINARY
Record             RECORD
Id                   LONG
                   END
                 END

  CODE
  IF UPPER(CLIP(COMMAND('1'))) = '--CREATE-EMPTY'
    TempBlobName = COMMAND('2')
    REMOVE(BlobFile)
    CREATE(BlobFile)
    RequireLong(ERRORCODE(),0,338)
    ExitProcess(0)
  END
  IF UPPER(CLIP(COMMAND('1'))) = '--VERIFY-EMPTY'
    Result = Parser.Init(COMMAND('2'))
    RequireLong(Result,0,339)
    RequireLong(Parser.Tables(),1,340)
    RequireLong(Parser.SetTable(1),0,341)
    RequireLong(Parser.Records(),0,342)
    ExitProcess(0)
  END
  IF UPPER(CLIP(COMMAND('1'))) = '--VERIFY-FALSE-PAGE-CANDIDATE'
    Result = Parser.Init(COMMAND('2'))
    RequireLong(Result,0,343)
    RequireLong(Parser.Tables(),1,344)
    RequireLong(Parser.SetTable(1),0,345)
    RequireLong(Parser.Records(),10001,346)
    ExitProcess(0)
  END
  CorruptFixtureRoot = COMMAND('1')
  IF ~CLIP(CorruptFixtureRoot)
    ExitProcess(320)
  END
  CorruptCountPath = CLIP(CorruptFixtureRoot) & '\CorruptCount.tmp'
  CorruptRlePath = CLIP(CorruptFixtureRoot) & '\CorruptRle.tmp'
  CorruptPagePath = CLIP(CorruptFixtureRoot) & '\CorruptPage.tmp'
  CorruptBlockRangePath = CLIP(CorruptFixtureRoot) & '\CorruptBlockRange.tmp'
  CorruptBlobPath = CLIP(CorruptFixtureRoot) & '\CorruptBlob.tmp'
  CorruptBlobNegativePath = CLIP(CorruptFixtureRoot) & '\CorruptBlobNegative.tmp'
  CorruptBlobMissingPath = CLIP(CorruptFixtureRoot) & '\CorruptBlobMissing.tmp'
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptCountPath)),TRUE,FALSE),TRUE,321)
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptRlePath)),TRUE,FALSE),TRUE,322)
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptPagePath)),TRUE,FALSE),TRUE,323)
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptBlockRangePath)),TRUE,FALSE),TRUE,327)
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptBlobPath)),TRUE,FALSE),TRUE,324)
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptBlobNegativePath)),TRUE,FALSE),TRUE,325)
  RequireLong(CHOOSE(EXISTS(CLIP(CorruptBlobMissingPath)),TRUE,FALSE),TRUE,326)

  Parser.SetProgressSink(MetadataProgress)
  Result = Parser.InitMetadata('tests\fixtures\COMPREHENSIVE.TPS')
  Parser.ClearProgressSink()
  RequireLong(Result,0,330)
  RequireLong(Parser.Tables(),1,331)
  RequireLong(Parser.SetTable(1),0,332)
  RequirePositive(Parser.Fields(),14,333)
  RequireLong(Parser.Keys(),1,334)
  RequireLong(Parser.Records(),0,335)
  RequireLong(MetadataProgress.SawDefinitions,TRUE,336)
  RequireLong(MetadataProgress.SawRecords,FALSE,337)
  RequirePositive(Parser.GetCurrentTableNumber(),1,354)
  RequirePositive(Parser.GetRecordLength(),1,355)
  RequireLong(Parser.GetFieldTypeCodeByNumber(Parser.GetFieldNumber('ID')),TpsFieldLong,356)
  RequireLong(Parser.GetFieldOffsetByNumber(Parser.GetFieldNumber('ID')),0,357)
  RequireLong(Parser.GetFieldLengthByNumber(Parser.GetFieldNumber('ID')),4,358)
  RequireLong(Parser.GetFieldIsMemoByNumber(Parser.GetFieldNumber('LARGEMEMO')),TRUE,359)
  RequireLong(Parser.GetFieldIsBlobByNumber(Parser.GetFieldNumber('LARGEMEMO')),FALSE,360)
  RequireLong(BAND(Parser.GetMemoFlagsByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsBlobFlag),TpsBlobFlag,361)
  RequireLong(Parser.GetFieldFlagsByNumber(0),0,362)
  RequireLong(Parser.GetFieldIndexByNumber(0),0,363)
  RequireString(Parser.GetFieldStringMaskByNumber(0),'',364)
  RequireString(Parser.GetExternalNameByNumber(0),'',365)
  RequireString(Parser.GetKeyExternalName(0),'',366)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\COMPREHENSIVE.TPS')
  RequireLong(Result,0,10)
  RequireLong(Parser.GetSourceEncrypted(),FALSE,367)
  RequireLong(Parser.GetRecoveryIssueCount(),0,368)
  RequireLong(Parser.Tables(),1,11)
  RequireString(CLIP(Parser.GetTableName(1)),'COMPREHENSIVE',12)
  RequireLong(Parser.SetTable(1),0,13)
  RequireLong(Parser.Records(),2,14)
  RequirePositive(Parser.Fields(),14,15)
  RequireLong(Parser.Keys(),1,16)
  RequireString(UPPER(CLIP(Parser.GetKeyName(1))),'SMP:BYID',17)
  RequireLong(BAND(Parser.GetKeyFlags(1),TpsKeyFlagPrimary),TpsKeyFlagPrimary,18)
  RequireLong(Parser.GetKeyFieldCount(1),1,19)
  RequireLong(Parser.GetKeyFieldIndex(1,1),0,24)
  RequireLong(Parser.GetKeyFieldAscending(1,1),TRUE,25)
  RequireLong(Parser.GetMemoLengthByNumber(Parser.GetFieldNumber('LARGEMEMO')),16384,26)
  RequireLong(Parser.GetFieldIsBlobByNumber(Parser.GetFieldNumber('LARGEBLOB')),TRUE,27)

  RequireLong(Parser.Get(1),0,30)
  RequirePositive(Parser.GetCurrentRecordNumber(),1,369)
  RequirePositive(Parser.GetCurrentRecordOffset(),1,370)
  RequireLong(Parser.GetLongField('ID'),1,31)
  ExpectedTime = (((11 * 60 * 60) + (7 * 60) + 13) * 100) + 42 + 1
  RequireLong(Parser.GetTimeField('MOMENT'),ExpectedTime,32)
  RequireString(CLIP(Parser.GetDecimalField('AMOUNT')),'0.12',33)
  RequireString(CLIP(Parser.GetStringField('FIXEDTEXT')),'AB',34)
  RequireString(CLIP(Parser.GetStringField('CSTRINGTEXT')),'CString',35)
  RequireString(CLIP(Parser.GetStringField('PSTRINGTEXT')),'Pascal',36)
  RequireLong(Parser.GetLongField('NUMBERS',1),11223344H,37)
  RequireLong(Parser.GetLongField('NUMBERS',2),55667788H,38)

  CLEAR(ExpectedGroup)
  ExpectedGroup[1 : 4] = 'G1  '
  ExpectedGroup[5] = CHR(04H)
  ExpectedGroup[6] = CHR(03H)
  ExpectedGroup[7] = CHR(02H)
  ExpectedGroup[8] = CHR(01H)
  ExpectedGroup[9] = CHR(00H)
  ExpectedGroup[10] = 'Z'
  GroupRaw = Parser.GetRawField('MIXED')
  GroupString = Parser.GetStringField('MIXED')
  LOOP I = 1 TO SIZE(ExpectedGroup)
    RequireLong(VAL(GroupRaw[I]),VAL(ExpectedGroup[I]),40 + I)
    RequireLong(VAL(GroupString[I]),VAL(ExpectedGroup[I]),60 + I)
  END
  RequireLong(Parser.GetLongField('GROUPNUMBER'),01020304H,71)
  RequireString(CLIP(Parser.GetStringField('GROUPTEXT')),'G1',72)

  MemoText = Parser.GetMemoField('LARGEMEMO')
  RequireLong(VAL(MemoText[1]),66,80)
  RequireLong(VAL(MemoText[12000]),79,81)

  BlobPreview = Parser.BlobPreviewByNumber(Parser.GetFieldNumber('LARGEBLOB'),SIZE(BlobPreview),BlobLength)
  RequireLong(BlobLength,40000,82)
  RequireLong(VAL(BlobPreview[1]),1,83)
  RequireLong(VAL(BlobPreview[16]),16,84)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateComplete,347)
  LargeRaw = Parser.GetBlobValueByNumber(Parser.GetFieldNumber('LARGEBLOB'),BlobLength)
  RequireLong(BlobLength,40000,379)
  RequireLong(VAL(LargeRaw[1]),1,380)
  RequireLong(VAL(LargeRaw[40000]),91,381)

  TempBlobName = CLIP(CorruptFixtureRoot) & '\ParserTestsBlob.tmp'
  REMOVE(BlobFile)
  CREATE(BlobFile)
  RequireLong(ERRORCODE(),0,90)
  OPEN(BlobFile)
  RequireLong(ERRORCODE(),0,91)
  CLEAR(BTF:Record)
  BTF:Id = 1
  ADD(BlobFile)
  RequireLong(ERRORCODE(),0,92)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,0,93)
  RequireLong(BTF:Payload{PROP:Size},40000,94)
  RequireLong(VAL(BTF:Payload[0]),1,95)
  RequireLong(VAL(BTF:Payload[39999]),91,96)
  CLOSE(BlobFile)
  REMOVE(BlobFile)

  RequireLong(Parser.Get(2),0,100)
  RequireLong(Parser.GetLongField('ID'),2,101)
  RequireLong(Parser.GetTimeField('MOMENT'),1,102)
  RequireString(CLIP(Parser.GetDecimalField('AMOUNT')),'0.00',103)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEMEMO')),TpsMemoStateEmpty,371)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateEmpty,372)
  Parser.Kill()

  Result = Parser.BuildFragmentedBlobFixture()
  RequireLong(Result,0,255)
  RequireLong(Parser.Records(),1,256)
  RequireLong(Parser.Get(1),0,257)
  RequireLong(Parser.GetMemoStateByNumber(1),TpsMemoStateComplete,258)
  FragmentedBlob = Parser.GetBlobValueByNumber(1,BlobLength)
  RequireLong(BlobLength,6,260)
  RequireString(FragmentedBlob,'ABCDEF',261)
  Parser.Kill()

  Result = Parser.BuildInvalidMemoFixture()
  RequireLong(Result,0,382)
  RequireLong(Parser.Get(1),0,383)
  RequireLong(Parser.GetMemoStateByNumber(1),TpsMemoStateDamaged,384)
  FragmentedBlob = Parser.GetBlobValueByNumber(1,BlobLength)
  RequireLong(BlobLength,0,385)
  RequireLong(Parser.GetErrorCode(),TpsErrBlobData,386)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\SUPERFILE.TPS')
  RequireLong(Result,0,230)
  RequireLong(Parser.Tables(),2,231)
  RequireLong(Parser.SetTable(1),0,232)
  RequireLong(Parser.Records(),1,233)
  RequirePositive(Parser.GetCurrentTableNumber(),1,373)
  RequirePositive(Parser.GetRecordLength(),1,374)
  RequireLong(Parser.Set(),0,234)
  RequireLong(Parser.Next(),FALSE,235)
  RequirePositive(Parser.GetCurrentRecordNumber(),1,236)
  RequireLong(Parser.GetLongField('ID'),1,237)
  RequireLong(Parser.Next(),TRUE,238)
  RequireLong(Parser.SetTable(2),0,239)
  RequireLong(Parser.Records(),1,240)
  RequireLong(Parser.Get(1),0,241)
  RequirePositive(Parser.GetCurrentRecordNumber(),1,242)
  RequireLong(Parser.GetLongField('ID'),10,243)
  RequireLong(Parser.SelectRawTableNumber(999),0,244)
  RequireLong(Parser.Records(),0,245)
  RequireLong(Parser.Set(),0,246)
  RequireLong(Parser.Next(),TRUE,247)
  RequireLong(Parser.Get(1),TpsErrRecordNotFound,248)
  RequireLong(Parser.SetTable(1),0,249)
  RequireLong(Parser.Records(),1,250)
  RequireLong(Parser.Get(1),0,251)
  RequireLong(Parser.GetLongField('ID'),1,252)
  Parser.Kill()
  RequireLong(Parser.Records(),0,253)
  RequireLong(Parser.Next(),TRUE,254)

  Result = Parser.Init('tests\fixtures\ENCRYPTED.TPS')
  RequireNonzero(Result,110)
  Result = Parser.Init('tests\fixtures\ENCRYPTED.TPS','sample-owner')
  RequireLong(Result,0,111)
  RequireLong(Parser.GetSourceEncrypted(),TRUE,375)
  RequireLong(Parser.Records(),2,112)
  Parser.Kill()
  Result = Parser.InitMetadata('tests\fixtures\ENCRYPTED.TPS','sample-owner')
  RequireLong(Result,0,338)
  RequireLong(Parser.GetSourceEncrypted(),TRUE,376)
  RequireLong(Parser.Tables(),1,339)
  RequireLong(Parser.Records(),0,340)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\COMPREHENSIVE.TPS','sample-owner')
  RequireLong(Result,0,120)
  RequireLong(Parser.GetSourceEncrypted(),FALSE,377)
  RequireLong(Parser.Records(),2,121)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\UNNAMED.TPS')
  RequireLong(Result,0,125)
  RequireString(CLIP(Parser.GetTableName(1)),'UNNAMED',126)
  RequireLong(Parser.Records(),1,127)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\LARGE_RECORD.TPS')
  RequireLong(Result,0,128)
  RequireLong(Parser.Records(),1,129)
  RequireLong(Parser.GetFieldSize('PAYLOAD'),40000,133)
  RequireLong(Parser.GetFieldNumber('VALUE'),0,20)
  RequireLong(Parser.GetErrorCode(),TpsErrFieldAmbiguous,21)
  RequirePositive(Parser.GetFieldNumber('A:VALUE'),1,22)
  RequirePositive(Parser.GetFieldNumber('B:VALUE'),1,23)
  RequireLong(Parser.Get(1),0,134)
  LargeRaw = Parser.GetRawField('PAYLOAD')
  RequireLong(VAL(LargeRaw[1]),76,135)
  RequireLong(VAL(LargeRaw[20000]),0,136)
  RequireLong(VAL(LargeRaw[40000]),90,137)
  Parser.Kill()

  Result = Parser.Init('CUSTOMER.TPS')
  RequireLong(Result,0,130)
  RequirePositive(Parser.Tables(),1,131)
  RequireString(CLIP(Parser.GetTableName(1)),'CUSTOMER',310)
  RequirePositive(Parser.Records(),1,132)
  Parser.Kill()

  Result = Parser.Init('ORDERS.TPS')
  RequireLong(Result,0,140)
  RequirePositive(Parser.Tables(),1,141)
  RequireString(CLIP(Parser.GetTableName(1)),'ORDERS',311)
  RequirePositive(Parser.Records(),1,142)
  Parser.Kill()

  Result = Parser.Init(CorruptCountPath)
  RequireNonzero(Result,150)
  Result = Parser.Init(CorruptCountPath,'',TRUE)
  RequireLong(Result,0,151)
  RequirePositive(Parser.Records(),1,152)
  Parser.Kill()

  Result = Parser.Init(CorruptBlockRangePath)
  RequireLong(Result,TpsErrBlockRange,387)
  Result = Parser.InitRecovering(CorruptBlockRangePath)
  RequireLong(Result,0,388)
  RequireLong(Parser.GetRecoveryIssueCount(),1,389)
  RequireLong(Parser.Records(),2,390)
  Parser.Kill()

  Result = Parser.Init(CorruptRlePath)
  RequireLong(Result,TpsErrRleInvalid,160)
  Result = Parser.InitRecovering(CorruptRlePath)
  RequireLong(Result,0,161)
  RequirePositive(Parser.GetRecoveryIssueCount(),1,378)
  RequirePositive(Parser.Records(),1,162)
  Parser.Kill()

  Result = Parser.Init(CorruptPagePath)
  RequireLong(Result,TpsErrPageInvalid,170)
  Result = Parser.InitRecovering(CorruptPagePath)
  RequireLong(Result,0,171)
  RequirePositive(Parser.Records(),1,172)
  Parser.Kill()

  Result = Parser.Init(CorruptBlobPath)
  RequireLong(Result,0,180)
  RequireLong(Parser.Get(1),0,181)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateDamaged,348)
  TempBlobName = CLIP(CorruptFixtureRoot) & '\ParserTestsBlob.tmp'
  REMOVE(BlobFile)
  CREATE(BlobFile)
  RequireLong(ERRORCODE(),0,182)
  OPEN(BlobFile)
  RequireLong(ERRORCODE(),0,183)
  CLEAR(BTF:Record)
  BTF:Id = 1
  ADD(BlobFile)
  RequireLong(ERRORCODE(),0,184)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,TpsErrBlobData,185)
  Parser.Kill()

  Result = Parser.InitRecovering(CorruptBlobPath)
  RequireLong(Result,0,186)
  RequireLong(Parser.Get(1),0,187)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateDamaged,349)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,0,188)
  RequireLong(BTF:Payload{PROP:Size},40000,189)
  CLOSE(BlobFile)
  REMOVE(BlobFile)
  Parser.Kill()

  Result = Parser.Init(CorruptBlobNegativePath)
  RequireLong(Result,0,200)
  RequireLong(Parser.Get(1),0,201)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateDamaged,350)
  TempBlobName = CLIP(CorruptFixtureRoot) & '\ParserTestsBlob.tmp'
  REMOVE(BlobFile)
  CREATE(BlobFile)
  RequireLong(ERRORCODE(),0,202)
  OPEN(BlobFile)
  RequireLong(ERRORCODE(),0,203)
  CLEAR(BTF:Record)
  BTF:Id = 1
  ADD(BlobFile)
  RequireLong(ERRORCODE(),0,204)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,TpsErrBlobData,205)
  Parser.Kill()

  Result = Parser.InitRecovering(CorruptBlobNegativePath)
  RequireLong(Result,0,206)
  RequireLong(Parser.Get(1),0,207)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateDamaged,351)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,0,208)
  RequireLong(BTF:Payload{PROP:Size},40000,209)
  CLOSE(BlobFile)
  REMOVE(BlobFile)
  Parser.Kill()

  Result = Parser.Init(CorruptBlobMissingPath)
  RequireLong(Result,0,220)
  RequireLong(Parser.Get(1),0,221)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateDamaged,352)
  TempBlobName = CLIP(CorruptFixtureRoot) & '\ParserTestsBlob.tmp'
  REMOVE(BlobFile)
  CREATE(BlobFile)
  RequireLong(ERRORCODE(),0,222)
  OPEN(BlobFile)
  RequireLong(ERRORCODE(),0,223)
  CLEAR(BTF:Record)
  BTF:Id = 1
  ADD(BlobFile)
  RequireLong(ERRORCODE(),0,224)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,TpsErrBlobData,225)
  Parser.Kill()

  Result = Parser.InitRecovering(CorruptBlobMissingPath)
  RequireLong(Result,0,226)
  RequireLong(Parser.Get(1),0,227)
  RequireLong(Parser.GetMemoStateByNumber(Parser.GetFieldNumber('LARGEBLOB')),TpsMemoStateDamaged,353)
  Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
  RequireLong(Result,0,228)
  RequireLong(BTF:Payload{PROP:Size},0,229)
  CLOSE(BlobFile)
  REMOVE(BlobFile)
  Parser.Kill()

  ExitProcess(0)

RegressionTpsParserType.BlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength)
  CODE
  RETURN SELF.GetBlobPreviewByNumber(pFieldNo,pMaxBytes,pBlobLength)

RegressionTpsParserType.SelectRawTableNumber PROCEDURE(LONG pTableNo)
  CODE
  SELF.CurrentTable = pTableNo
  RETURN SELF.Set(0)

RegressionTpsParserType.BuildFragmentedBlobFixture PROCEDURE
  CODE
  SELF.Kill()
  CLEAR(SELF.DataQ)
  SELF.DataQ.TableNo = 1
  SELF.DataQ.RecordNumber = 42
  SELF.DataQ.PayloadLen = 1
  SELF.DataQ.Payload &= NEW(STRING(1))
  SELF.DataQ.Payload[1] = CHR(0)
  ADD(SELF.DataQ)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SELF.FieldQ)
  SELF.FieldQ.TableNo = 1
  SELF.FieldQ.FieldNo = 1
  SELF.FieldQ.Name &= NEW(STRING(4))
  SELF.FieldQ.Name = 'Blob'
  SELF.FieldQ.ShortName &= NEW(STRING(4))
  SELF.FieldQ.ShortName = 'Blob'
  SELF.FieldQ.TypeName = 'BLOB'
  SELF.FieldQ.IsBlob = TRUE
  SELF.FieldQ.MemoIndex = 0
  ADD(SELF.FieldQ)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SELF.MemoQ)
  SELF.MemoQ.TableNo = 1
  SELF.MemoQ.Owner = 42
  SELF.MemoQ.MemoIndex = 0
  SELF.MemoQ.Sequence = 2
  SELF.MemoQ.DataLen = 4
  SELF.MemoQ.Payload &= NEW(STRING(4))
  SELF.MemoQ.Payload = 'CDEF'
  SELF.MemoQ.Arrival = 3
  ADD(SELF.MemoQ)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SELF.MemoQ)
  SELF.MemoQ.TableNo = 1
  SELF.MemoQ.Owner = 42
  SELF.MemoQ.MemoIndex = 0
  SELF.MemoQ.Sequence = 0
  SELF.MemoQ.DataLen = 2
  SELF.MemoQ.Payload &= NEW(STRING(2))
  SELF.MemoQ.Payload[1] = CHR(6)
  SELF.MemoQ.Payload[2] = CHR(0)
  SELF.MemoQ.Arrival = 1
  ADD(SELF.MemoQ)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SELF.MemoQ)
  SELF.MemoQ.TableNo = 1
  SELF.MemoQ.Owner = 42
  SELF.MemoQ.MemoIndex = 0
  SELF.MemoQ.Sequence = 1
  SELF.MemoQ.DataLen = 4
  SELF.MemoQ.Payload &= NEW(STRING(4))
  SELF.MemoQ.Payload[1] = CHR(0)
  SELF.MemoQ.Payload[2] = CHR(0)
  SELF.MemoQ.Payload[3 : 4] = 'XX'
  SELF.MemoQ.Arrival = 2
  ADD(SELF.MemoQ)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  CLEAR(SELF.MemoQ)
  SELF.MemoQ.TableNo = 1
  SELF.MemoQ.Owner = 42
  SELF.MemoQ.MemoIndex = 0
  SELF.MemoQ.Sequence = 1
  SELF.MemoQ.DataLen = 4
  SELF.MemoQ.Payload &= NEW(STRING(4))
  SELF.MemoQ.Payload[1] = CHR(0)
  SELF.MemoQ.Payload[2] = CHR(0)
  SELF.MemoQ.Payload[3 : 4] = 'AB'
  SELF.MemoQ.Arrival = 4
  ADD(SELF.MemoQ)
  IF ERRORCODE()
    RETURN ERRORCODE()
  END
  SELF.CurrentTable = 1
  RETURN SELF.Set(0)

RegressionTpsParserType.BuildInvalidMemoFixture PROCEDURE
InvalidMemoIndex                                   LONG
InvalidMemoResult                                  LONG
  CODE
  InvalidMemoResult = SELF.BuildFragmentedBlobFixture()
  IF InvalidMemoResult <> 0
    RETURN InvalidMemoResult
  END
  LOOP InvalidMemoIndex = 1 TO RECORDS(SELF.MemoQ)
    GET(SELF.MemoQ,InvalidMemoIndex)
    IF SELF.MemoQ.Sequence = 2
      SELF.MemoQ.DataLen = SIZE(SELF.MemoQ.Payload) + 1
      PUT(SELF.MemoQ)
      RETURN 0
    END
  END
  RETURN 1

RequireLong PROCEDURE(LONG pActual,LONG pExpected,LONG pCode)
  CODE
  IF pActual <> pExpected
    ExitProcess(pCode)
  END

RequireString PROCEDURE(STRING pActual,STRING pExpected,LONG pCode)
  CODE
  IF pActual <> pExpected
    ExitProcess(pCode)
  END

RequirePositive PROCEDURE(LONG pActual,LONG pMinimum,LONG pCode)
  CODE
  IF pActual < pMinimum
    ExitProcess(pCode)
  END

RequireNonzero PROCEDURE(LONG pActual,LONG pCode)
  CODE
  IF pActual = 0
    ExitProcess(pCode)
  END

MetadataProgressProbeType.Update PROCEDURE(STRING pStage,LONG pCompleted,LONG pTotal)
  CODE
  IF UPPER(CLIP(pStage)) = 'SCANNING DEFINITIONS'
    SELF.SawDefinitions = TRUE
  ELSIF UPPER(CLIP(pStage)) = 'SCANNING RECORDS AND MEMO/BLOB DATA'
    SELF.SawRecords = TRUE
  END
