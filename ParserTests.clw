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
                      END

Parser           RegressionTpsParserType
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
TempBlobName     STRING(260)

BlobFile         FILE,DRIVER('TOPSPEED'),NAME(TempBlobName),PRE(BTF),CREATE
Payload            BLOB,BINARY
Record             RECORD
Id                   LONG
                   END
                 END

  CODE
  Result = Parser.Init('tests\fixtures\COMPREHENSIVE.TPS')
  RequireLong(Result,0,10)
  RequireLong(Parser.Tables(),1,11)
  RequireString(UPPER(CLIP(Parser.GetTableName(1))),'SMP',12)
  RequireLong(Parser.SetTable(1),0,13)
  RequireLong(Parser.Records(),2,14)
  RequirePositive(Parser.Fields(),14,15)

  RequireLong(Parser.Get(1),0,30)
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

  TempBlobName = 'tests\ParserTestsBlob.tmp'
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
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\ENCRYPTED.TPS')
  RequireNonzero(Result,110)
  Result = Parser.Init('tests\fixtures\ENCRYPTED.TPS','sample-owner')
  RequireLong(Result,0,111)
  RequireLong(Parser.Records(),2,112)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\COMPREHENSIVE.TPS','sample-owner')
  RequireLong(Result,0,120)
  RequireLong(Parser.Records(),2,121)
  Parser.Kill()

  Result = Parser.Init('tests\fixtures\UNNAMED.TPS')
  RequireLong(Result,0,125)
  RequireString(CLIP(Parser.GetTableName(1)),'1',126)
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
  RequirePositive(Parser.Records(),1,132)
  Parser.Kill()

  Result = Parser.Init('ORDERS.TPS')
  RequireLong(Result,0,140)
  RequirePositive(Parser.Tables(),1,141)
  RequirePositive(Parser.Records(),1,142)
  Parser.Kill()

  IF EXISTS('tests\CorruptCount.tmp')
    Result = Parser.Init('tests\CorruptCount.tmp')
    RequireNonzero(Result,150)
    Result = Parser.Init('tests\CorruptCount.tmp','',TRUE)
    RequireLong(Result,0,151)
    RequirePositive(Parser.Records(),1,152)
    Parser.Kill()
  END

  IF EXISTS('tests\CorruptRle.tmp')
    Result = Parser.Init('tests\CorruptRle.tmp')
    RequireLong(Result,TpsErrRleInvalid,160)
    Result = Parser.InitRecovering('tests\CorruptRle.tmp')
    RequireLong(Result,0,161)
    RequirePositive(Parser.Records(),1,162)
    Parser.Kill()
  END

  IF EXISTS('tests\CorruptPage.tmp')
    Result = Parser.Init('tests\CorruptPage.tmp')
    RequireLong(Result,TpsErrPageInvalid,170)
    Result = Parser.InitRecovering('tests\CorruptPage.tmp')
    RequireLong(Result,0,171)
    RequirePositive(Parser.Records(),1,172)
    Parser.Kill()
  END

  IF EXISTS('tests\CorruptBlob.tmp')
    Result = Parser.Init('tests\CorruptBlob.tmp')
    RequireLong(Result,0,180)
    RequireLong(Parser.Get(1),0,181)
    TempBlobName = 'tests\ParserTestsBlob.tmp'
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

    Result = Parser.InitRecovering('tests\CorruptBlob.tmp')
    RequireLong(Result,0,186)
    RequireLong(Parser.Get(1),0,187)
    Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
    RequireLong(Result,0,188)
    RequireLong(BTF:Payload{PROP:Size},40000,189)
    CLOSE(BlobFile)
    REMOVE(BlobFile)
    Parser.Kill()
  END

  IF EXISTS('tests\CorruptBlobNegative.tmp')
    Result = Parser.Init('tests\CorruptBlobNegative.tmp')
    RequireLong(Result,0,200)
    RequireLong(Parser.Get(1),0,201)
    TempBlobName = 'tests\ParserTestsBlob.tmp'
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

    Result = Parser.InitRecovering('tests\CorruptBlobNegative.tmp')
    RequireLong(Result,0,206)
    RequireLong(Parser.Get(1),0,207)
    Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
    RequireLong(Result,0,208)
    RequireLong(BTF:Payload{PROP:Size},40000,209)
    CLOSE(BlobFile)
    REMOVE(BlobFile)
    Parser.Kill()
  END

  IF EXISTS('tests\CorruptBlobMissing.tmp')
    Result = Parser.Init('tests\CorruptBlobMissing.tmp')
    RequireLong(Result,0,220)
    RequireLong(Parser.Get(1),0,221)
    TempBlobName = 'tests\ParserTestsBlob.tmp'
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

    Result = Parser.InitRecovering('tests\CorruptBlobMissing.tmp')
    RequireLong(Result,0,226)
    RequireLong(Parser.Get(1),0,227)
    Result = Parser.GetBlobField('LARGEBLOB',BTF:Payload)
    RequireLong(Result,0,228)
    RequireLong(BTF:Payload{PROP:Size},0,229)
    CLOSE(BlobFile)
    REMOVE(BlobFile)
    Parser.Kill()
  END

  ExitProcess(0)

RegressionTpsParserType.BlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength)
  CODE
  RETURN SELF.GetBlobPreviewByNumber(pFieldNo,pMaxBytes,pBlobLength)

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

