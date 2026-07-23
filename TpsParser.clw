! ------------------------------------------------------------------------------
! TpsParserType
!
! Clarion TPS parser adapted from the Java ctrl-alt-dev/tps-parse project.
!
! Original project:
!   https://github.com/ctrl-alt-dev/tps-parse
!   Copyright (C) 2012-2021 E. Hooijmeijer / Erik Hooijmeijer
!   Licensed under the Apache License 2.0
!
! Local license copy:
!   Apache-2.0.txt
!
! Note:
!   TPS parsing is based on reverse-engineered file structures and may be
!   incomplete or misinterpret data. Verify output before relying on it.
! ------------------------------------------------------------------------------

  MEMBER

  MAP
  END

  INCLUDE('TpsParser.inc'),ONCE

TpsWorkSlack        EQUATE(8192)
TpsFileNameMax      EQUATE(260)
TpsDosBufferMax     EQUATE(32768)
TpsDosReadMode      EQUATE(40H)
TpsMinHeaderLen     EQUATE(200H)
TpsBlockStartTable  EQUATE(20H)
TpsBlockEndTable    EQUATE(110H)
TpsFirstPageOffset  EQUATE(200H)
TpsPageScanStep     EQUATE(100H)
TpsAlignMask        EQUATE(0FFFFFF00H)
TpsBlockAddrShift   EQUATE(8)
TpsPageHeaderLen    EQUATE(13)
TpsSignatureOffset  EQUATE(14)
TpsSignatureLen     EQUATE(4)
TpsRecData          EQUATE(0F3H)
TpsRecMemo          EQUATE(0FCH)
TpsRecTableDef      EQUATE(0FAH)
TpsRecTableName     EQUATE(0FEH)
TpsFieldByte        EQUATE(1)
TpsFieldShort       EQUATE(2)
TpsFieldUShort      EQUATE(3)
TpsFieldDate        EQUATE(4)
TpsFieldTime        EQUATE(5)
TpsFieldLong        EQUATE(6)
TpsFieldULong       EQUATE(7)
TpsFieldFloat       EQUATE(8)
TpsFieldDouble      EQUATE(9)
TpsFieldBcd         EQUATE(0AH)
TpsFieldString      EQUATE(12H)
TpsFieldCString     EQUATE(13H)
TpsFieldPString     EQUATE(14H)
TpsFieldGroup       EQUATE(16H)
TpsMemoFieldType    EQUATE(0FCH)
TpsBlobFlag         EQUATE(4)
TpsBlobLenPrefix    EQUATE(4)
TpsFlagRecLen       EQUATE(128)
TpsFlagHeaderLen    EQUATE(64)
TpsFlagCopyLen      EQUATE(63)
TpsRleExtended      EQUATE(127)
TpsRleBase          EQUATE(128)
TpsKeySize          EQUATE(64)
TpsKeyWords         EQUATE(16)
TpsKeyIndexMask     EQUATE(3FH)
TpsKeyByteStep      EQUATE(11H)
TpsHeaderDecryptLen EQUATE(200H)
TpsByteMask         EQUATE(0FFH)
TpsWordNotMask      EQUATE(0FFFFFFFFH)
TpsPassMetadata     EQUATE(1)
TpsPassContent      EQUATE(2)

TpsParserType.Init  PROCEDURE(STRING pFileName)
  CODE
  RETURN SELF.InitCore(pFileName,'',FALSE,FALSE)

TpsParserType.Init  PROCEDURE(STRING pFileName,STRING pOwner)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,FALSE)

TpsParserType.InitRecovering  PROCEDURE(STRING pFileName)
  CODE
  RETURN SELF.InitCore(pFileName,'',FALSE,TRUE)

TpsParserType.Init  PROCEDURE(STRING pFileName,STRING pOwner,BYTE pIgnoreErrors)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,pIgnoreErrors)

TpsParserType.InitRecovering  PROCEDURE(STRING pFileName,STRING pOwner)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,TRUE)

TpsParserType.InitCore PROCEDURE(STRING pFileName,STRING pOwner,BYTE pHasOwner,BYTE pIgnoreErrors)
Result                LONG
  CODE
  SELF.Kill()
  SELF.LastError = 0
  SELF.IgnoreErrors = pIgnoreErrors
  Result = SELF.LoadSource(pFileName)
  IF Result <> 0
    RETURN Result
  END
  IF pHasOwner
    Result = SELF.ValidateHeader()
    IF Result <> 0
      Result = SELF.SetLastError(0,'')
      Result = SELF.DecryptSource(pOwner)
      IF Result <> 0
        RETURN Result
      END
    END
  END
  Result = SELF.ParseTps()
  IF Result <> 0
    RETURN Result
  END
  SORT(SELF.TableDefQ,+SELF.TableDefQ.TableNo,+SELF.TableDefQ.BlockNo)
  SORT(SELF.DataQ,+SELF.DataQ.TableNo,+SELF.DataQ.RecordNumber)
  SORT(SELF.MemoQ,+SELF.MemoQ.TableNo,+SELF.MemoQ.Owner,+SELF.MemoQ.MemoIndex,+SELF.MemoQ.Sequence)
  Result = SELF.SetTable(0)
  IF Result <> 0
    RETURN Result
  END
  RETURN SELF.SetLastError(0,'')

TpsParserType.Kill  PROCEDURE
  CODE
  IF ~SELF.Src &= NULL
    DISPOSE(SELF.Src)
  END
  IF ~SELF.WorkPage &= NULL
    DISPOSE(SELF.WorkPage)
  END
  SELF.FreeData()
  SELF.FreeMemos()
  SELF.FreeTableDefs()
  SELF.FreeTableNames()
  SELF.FreeFields()
  IF ~SELF.ReturnBuffer &= NULL
    DISPOSE(SELF.ReturnBuffer)
  END
  IF ~SELF.BlobPreviewBuffer &= NULL
    DISPOSE(SELF.BlobPreviewBuffer)
  END
  IF ~SELF.LastErrorText &= NULL
    DISPOSE(SELF.LastErrorText)
  END
  SELF.SrcLen = 0
  SELF.WorkPageLen = 0
  SELF.CurrentRecord = 0
  SELF.CurrentTable = 0
  SELF.IgnoreErrors = FALSE
  SELF.ParsePass = 0
  SELF.Arrival = 0

TpsParserType.GetErrorCode  PROCEDURE
  CODE
  RETURN SELF.LastError

TpsParserType.GetError  PROCEDURE
  CODE
  IF SELF.LastErrorText &= NULL
    RETURN ''
  END
  RETURN SELF.LastErrorText

TpsParserType.Tables    PROCEDURE
I                         LONG
Count                     LONG
LastNo                    LONG
TotalLen                  LONG
  CODE
  SORT(SELF.TableDefQ,+SELF.TableDefQ.TableNo,+SELF.TableDefQ.BlockNo)
  Count = 0
  LastNo = -1
  LOOP I = 1 TO RECORDS(SELF.TableDefQ)
    GET(SELF.TableDefQ,I)
    IF SELF.TableDefQ.TableNo <> LastNo
      LastNo = SELF.TableDefQ.TableNo
      IF SELF.TableDefinitionIsComplete(LastNo,TotalLen)
        Count += 1
      END
    END
  END
  RETURN Count

TpsParserType.GetTableName  PROCEDURE(LONG pTableIndex)
TableNo                       LONG
  CODE
  TableNo = SELF.ResolveTableNumber(pTableIndex)
  RETURN SELF.GetTableNameByTableNumber(TableNo)

TpsParserType.SetTable  PROCEDURE(LONG pTableIndex)
TableNo                   LONG
Result                    LONG
  CODE
  IF pTableIndex = 0
    pTableIndex = 1
  END
  TableNo = SELF.ResolveTableNumber(pTableIndex)
  IF TableNo = 0
    RETURN SELF.SetLastError(TpsErrTableIndex,'Invalid table index ' & pTableIndex & '; table count=' & SELF.Tables())
  END
  SELF.CurrentTable = TableNo
  SELF.CurrentRecord = 0
  Result = SELF.ParseTableLayout()
  IF Result <> 0
    RETURN Result
  END
  RETURN SELF.SetLastError(0,'')

TpsParserType.Records   PROCEDURE
I                         LONG
Count                     LONG
  CODE
  Count = 0
  LOOP I = 1 TO RECORDS(SELF.DataQ)
    GET(SELF.DataQ,I)
    IF SELF.DataQ.TableNo = SELF.CurrentTable
      Count += 1
    END
  END
  RETURN Count

TpsParserType.Get   PROCEDURE(LONG pRecordNo)
I                     LONG
Count                 LONG
  CODE
  IF pRecordNo < 1
    SELF.CurrentRecord = 0
    RETURN SELF.SetLastError(TpsErrRecordIndex,'Invalid record index ' & pRecordNo)
  END
  Count = 0
  LOOP I = 1 TO RECORDS(SELF.DataQ)
    GET(SELF.DataQ,I)
    IF SELF.DataQ.TableNo = SELF.CurrentTable
      Count += 1
      IF Count = pRecordNo
        SELF.CurrentRecord = I
        RETURN SELF.SetLastError(0,'')
      END
    END
  END
  SELF.CurrentRecord = 0
  RETURN SELF.SetLastError(TpsErrRecordNotFound,'Record index not found ' & pRecordNo & '; record count=' & Count)

TpsParserType.Set   PROCEDURE(LONG pRecordNo)
  CODE
  IF pRecordNo = 0
    SELF.CurrentRecord = 0
    RETURN SELF.SetLastError(0,'')
  END
  RETURN SELF.Get(pRecordNo)

TpsParserType.Next  PROCEDURE
  CODE
  LOOP
    SELF.CurrentRecord += 1
    IF SELF.CurrentRecord > RECORDS(SELF.DataQ)
      SELF.CurrentRecord = 0
      RETURN TRUE
    END
    GET(SELF.DataQ,SELF.CurrentRecord)
    IF SELF.DataQ.TableNo = SELF.CurrentTable
      RETURN FALSE
    END
  END

TpsParserType.Fields    PROCEDURE
  CODE
  RETURN RECORDS(SELF.FieldQ)

TpsParserType.GetFieldNameByNumber  PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN CLIP(SELF.FieldQ.ShortName)

TpsParserType.GetFieldType  PROCEDURE(STRING pFieldName)
  CODE
  RETURN SELF.GetFieldTypeByNumber(SELF.GetFieldNumber(pFieldName))

TpsParserType.GetFieldTypeByNumber  PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN CLIP(SELF.FieldQ.TypeName)

TpsParserType.GetFieldDimension PROCEDURE(STRING pFieldName)
  CODE
  RETURN SELF.GetFieldDimensionByNumber(SELF.GetFieldNumber(pFieldName))

TpsParserType.GetFieldDimensionByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.Elements > 1
    RETURN SELF.FieldQ.Elements
  END
  RETURN 0

TpsParserType.GetFieldSize  PROCEDURE(STRING pFieldName)
  CODE
  RETURN SELF.GetFieldSizeByNumber(SELF.GetFieldNumber(pFieldName))

TpsParserType.GetFieldSizeByNumber  PROCEDURE(LONG pFieldNo)
ElementLen                            LONG
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.IsMemo OR SELF.FieldQ.IsBlob
    RETURN 0
  END
  CASE SELF.FieldQ.FieldType
    OF TpsFieldBcd
      RETURN SELF.FieldQ.BcdLengthOfElement
    ELSE
      ElementLen = SELF.FieldQ.Length
      IF SELF.FieldQ.Elements > 1
        ElementLen = SELF.FieldQ.Length / SELF.FieldQ.Elements
      END
      RETURN ElementLen
  END

TpsParserType.GetFieldDecimals  PROCEDURE(STRING pFieldName)
  CODE
  RETURN SELF.GetFieldDecimalsByNumber(SELF.GetFieldNumber(pFieldName))

TpsParserType.GetFieldDecimalsByNumber  PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.FieldType = TpsFieldBcd
    RETURN SELF.FieldQ.BcdDigitsAfterDecimal
  END
  RETURN 0

TpsParserType.GetFieldNumber    PROCEDURE(STRING pFieldName)
I                                 LONG
Found                             LONG
Matches                           LONG
  CODE
  LOOP I = 1 TO RECORDS(SELF.FieldQ)
    GET(SELF.FieldQ,I)
    IF SELF.FieldQ.TableNo = SELF.CurrentTable
      IF UPPER(CLIP(SELF.FieldQ.ShortName)) = UPPER(CLIP(pFieldName)) OR UPPER(CLIP(SELF.FieldQ.Name)) = UPPER(CLIP(pFieldName))
        Found = I
        Matches += 1
      END
    END
  END
  IF Matches > 1
    Found = SELF.SetLastError(TpsErrFieldAmbiguous,'Ambiguous field, MEMO, or BLOB name "' & CLIP(pFieldName) & '" in table=' & SELF.CurrentTable)
    RETURN 0
  END
  IF Matches = 1
    RETURN Found
  END
  RETURN 0

TpsParserType.GetField  PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.IsMemo
    RETURN SELF.GetMemoFieldByNumber(pFieldNo)
  END
  IF SELF.FieldQ.IsBlob
    RETURN ''
  END
  CASE SELF.FieldQ.FieldType
    OF TpsFieldByte
      RETURN SELF.GetByteFieldByNumber(pFieldNo,pDimension)
    OF TpsFieldShort
      RETURN SELF.GetShortFieldByNumber(pFieldNo,pDimension)
    OF TpsFieldUShort
      RETURN SELF.GetUShortFieldByNumber(pFieldNo,pDimension)
    OF TpsFieldDate
      RETURN FORMAT(SELF.GetDateFieldByNumber(pFieldNo,pDimension),@D10-B)
    OF TpsFieldTime
      RETURN FORMAT(SELF.GetTimeFieldByNumber(pFieldNo,pDimension),@T04B)
    OF TpsFieldLong
      RETURN SELF.GetLongFieldByNumber(pFieldNo,pDimension)
    OF TpsFieldULong
      RETURN SELF.GetULongFieldByNumber(pFieldNo,pDimension)
    OF TpsFieldFloat OROF TpsFieldDouble
      RETURN SELF.GetRealFieldByNumber(pFieldNo,pDimension)
    OF TpsFieldBcd
      RETURN SELF.GetDecimalFieldByNumber(pFieldNo,pDimension)
    ELSE
      RETURN SELF.GetStringFieldByNumber(pFieldNo,pDimension)
  END

TpsParserType.GetStringField    PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetStringFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetStringFieldByNumber    PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                    LONG
Length                                    LONG
I                                         LONG
B                                         LONG
StrLen                                    LONG
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  GET(SELF.DataQ,SELF.CurrentRecord)
  CASE SELF.FieldQ.FieldType
    OF TpsFieldCString
      StrLen = 0
      LOOP I = 0 TO Length - 1
        B = SELF.ReadByte(SELF.DataQ.Payload,Offset + I)
        IF B = 0
          BREAK
        END
        StrLen += 1
      END
      RETURN SELF.SetReturnBuffer(SELF.DataQ.Payload,Offset,StrLen)
    OF TpsFieldPString
      IF Length < 1
        RETURN ''
      END
      StrLen = SELF.ReadByte(SELF.DataQ.Payload,Offset)
      IF StrLen > Length - 1
        B = SELF.SetLastError(TpsErrFieldDataInvalid,'Invalid PSTRING length=' & StrLen & '; available=' & Length - 1)
        RETURN ''
      END
      IF StrLen = 0
        RETURN ''
      END
      RETURN SELF.SetReturnBuffer(SELF.DataQ.Payload,Offset + 1,StrLen)
    OF TpsFieldString
      RETURN SELF.TrimFixedString(SELF.DataQ.Payload,Offset,Length)
    ELSE
      RETURN SELF.SetReturnBuffer(SELF.DataQ.Payload,Offset,Length)
  END

TpsParserType.GetByteField  PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetByteFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetByteFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                LONG
Length                                LONG
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN 0
  END
  IF Length < 1
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.ReadByte(SELF.DataQ.Payload,Offset)

TpsParserType.GetShortField PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetShortFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetShortFieldByNumber PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                LONG
Length                                LONG
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN 0
  END
  IF Length < 2
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.ReadLeShort(SELF.DataQ.Payload,Offset)

TpsParserType.GetUShortField    PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetUShortFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetUShortFieldByNumber    PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                    LONG
Length                                    LONG
U                                         USHORT
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN 0
  END
  IF Length < 2
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  U = SELF.ReadLeShort(SELF.DataQ.Payload,Offset)
  RETURN U

TpsParserType.GetLongField  PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetLongFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetLongFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                LONG
Length                                LONG
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN 0
  END
  IF Length < 4
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.ReadLeLong(SELF.DataQ.Payload,Offset)

TpsParserType.GetULongField PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetULongFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetULongFieldByNumber PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                LONG
Length                                LONG
U                                     ULONG
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN 0
  END
  IF Length < 4
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  U = SELF.ReadLeLong(SELF.DataQ.Payload,Offset)
  RETURN U

TpsParserType.GetRealField  PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetRealFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetRealFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                LONG
Length                                LONG
FloatValue                            GROUP
Bytes                                   STRING(4)
Value                                   SREAL,OVER(Bytes)
                                      END
DoubleValue                           GROUP
Bytes                                   STRING(8)
Value                                   REAL,OVER(Bytes)
                                      END
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  GET(SELF.DataQ,SELF.CurrentRecord)
  CASE SELF.FieldQ.FieldType
    OF TpsFieldFloat
      IF Length < 4
        RETURN 0
      END
      FloatValue.Bytes = SELF.DataQ.Payload[Offset + 1 : Offset + 4]
      RETURN FloatValue.Value
    OF TpsFieldDouble
      IF Length < 8
        RETURN 0
      END
      DoubleValue.Bytes = SELF.DataQ.Payload[Offset + 1 : Offset + 8]
      RETURN DoubleValue.Value
    ELSE
      RETURN 0
  END

TpsParserType.GetDecimalField   PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetDecimalFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetDecimalFieldByNumber   PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                    LONG
Length                                    LONG
I                                         LONG
B                                         LONG
Digits                                    &STRING
Out                                       &STRING
DigitLen                                  LONG
IntegerEnd                                LONG
StartPos                                  LONG
OutLen                                    LONG
SignChar                                  STRING(1)
  CODE
  Digits &= NULL
  Out &= NULL
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  GET(SELF.DataQ,SELF.CurrentRecord)
  IF SELF.FieldQ.FieldType <> TpsFieldBcd
    RETURN ''
  END
  DigitLen = Length * 2
  IF DigitLen < 2
    RETURN ''
  END
  Digits &= NEW(STRING(DigitLen))
  DigitLen = 0
  LOOP I = 0 TO Length - 1
    B = SELF.ReadByte(SELF.DataQ.Payload,Offset + I)
    DigitLen += 1
    Digits[DigitLen] = CHOOSE(BSHIFT(B,-4) < 10,CHR(48 + BSHIFT(B,-4)),CHR(55 + BSHIFT(B,-4)))
    DigitLen += 1
    Digits[DigitLen] = CHOOSE(BAND(B,0FH) < 10,CHR(48 + BAND(B,0FH)),CHR(55 + BAND(B,0FH)))
  END
  SignChar = Digits[1]
  Out &= NEW(STRING(DigitLen + 2))
  CLEAR(Out)
  OutLen = 0
  IF SignChar <> '0'
    OutLen += 1
    Out[OutLen] = '-'
  END
  IntegerEnd = DigitLen - SELF.FieldQ.BcdDigitsAfterDecimal
  StartPos = 2
  LOOP WHILE StartPos <= IntegerEnd AND Digits[StartPos] = '0'
    StartPos += 1
  END
  IF StartPos > IntegerEnd
    OutLen += 1
    Out[OutLen] = '0'
  ELSE
    Out[OutLen + 1 : OutLen + IntegerEnd - StartPos + 1] = Digits[StartPos : IntegerEnd]
    OutLen += IntegerEnd - StartPos + 1
  END
  IF SELF.FieldQ.BcdDigitsAfterDecimal > 0
    OutLen += 1
    Out[OutLen] = '.'
    Out[OutLen + 1 : OutLen + SELF.FieldQ.BcdDigitsAfterDecimal] = Digits[IntegerEnd + 1 : DigitLen]
    OutLen += SELF.FieldQ.BcdDigitsAfterDecimal
  END
  B = LEN(SELF.SetReturnBuffer(Out,0,OutLen))
  DISPOSE(Digits)
  DISPOSE(Out)
  RETURN SELF.ReturnBuffer

TpsParserType.GetRawField   PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetRawFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetRawFieldByNumber   PROCEDURE(LONG pFieldNo,LONG pDimension)
Offset                                LONG
Length                                LONG
  CODE
  IF SELF.ResolveFieldValue(pFieldNo,pDimension,Offset,Length)
    RETURN ''
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.Slice(SELF.DataQ.Payload,Offset,Length)

TpsParserType.GetDateField  PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetDateFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetDateFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension)
  CODE
  RETURN SELF.TpsDateToClarion(SELF.GetLongFieldByNumber(pFieldNo,pDimension))

TpsParserType.GetTimeField  PROCEDURE(STRING pFieldName,LONG pDimension)
  CODE
  RETURN SELF.GetTimeFieldByNumber(SELF.GetFieldNumber(pFieldName),pDimension)

TpsParserType.GetTimeFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension)
  CODE
  RETURN SELF.TpsTimeToClarion(SELF.GetLongFieldByNumber(pFieldNo,pDimension))

TpsParserType.GetMemoField  PROCEDURE(STRING pFieldName)
  CODE
  RETURN SELF.GetMemoFieldByNumber(SELF.GetFieldNumber(pFieldName))

TpsParserType.GetMemoFieldByNumber  PROCEDURE(LONG pFieldNo)
Owner                                 LONG
MemoIndex                             LONG
RawLen                                LONG
  CODE
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ) OR pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  IF ~SELF.FieldQ.IsMemo
    RETURN ''
  END
  MemoIndex = SELF.FieldQ.MemoIndex
  GET(SELF.DataQ,SELF.CurrentRecord)
  Owner = SELF.DataQ.RecordNumber
  IF ~SELF.MemoIsComplete(Owner,MemoIndex,RawLen) OR RawLen < 1
    RETURN ''
  END
  IF ~SELF.ReturnBuffer &= NULL
    DISPOSE(SELF.ReturnBuffer)
  END
  SELF.ReturnBuffer &= NEW(STRING(RawLen))
  RawLen = SELF.CopyMemoRaw(Owner,MemoIndex,SELF.ReturnBuffer,RawLen)
  IF RawLen < 1
    RETURN ''
  END
  RETURN SELF.ReturnBuffer

TpsParserType.GetBlobField  PROCEDURE(STRING pFieldName,*BLOB pBlob)
  CODE
  RETURN SELF.GetBlobFieldByNumber(SELF.GetFieldNumber(pFieldName),pBlob)

TpsParserType.GetBlobFieldByNumber  PROCEDURE(LONG pFieldNo,*BLOB pBlob)
BlobLen                               LONG
Result                                LONG
  CODE
  Result = SELF.LoadBlobPreviewByNumber(pFieldNo,7FFFFFFFH,BlobLen)
  IF Result <> 0
    pBlob{PROP:Size} = 0
    pBlob{PROP:Touched} = TRUE
    RETURN Result
  END
  pBlob{PROP:Size} = BlobLen
  IF BlobLen > 0 AND NOT (SELF.BlobPreviewBuffer &= NULL)
    pBlob[0 : BlobLen - 1] = SELF.BlobPreviewBuffer[1 : BlobLen]
  END
  IF ~SELF.BlobPreviewBuffer &= NULL
    DISPOSE(SELF.BlobPreviewBuffer)
  END
  pBlob{PROP:Touched} = TRUE
  RETURN SELF.SetLastError(0,'')

TpsParserType.GetBlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength)
Result                                  LONG
  CODE
  Result = SELF.LoadBlobPreviewByNumber(pFieldNo,pMaxBytes,pBlobLength)
  IF Result <> 0 OR SELF.BlobPreviewBuffer &= NULL
    RETURN ''
  END
  RETURN SELF.BlobPreviewBuffer

TpsParserType.LoadBlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength)
Owner                                 LONG
MemoIndex                             LONG
RawLen                                LONG
BlobLen                               LONG
Avail                                 LONG
PreviewLen                            LONG
CopyLen                               LONG
Raw                                   &STRING
  CODE
  pBlobLength = 0
  IF ~SELF.BlobPreviewBuffer &= NULL
    DISPOSE(SELF.BlobPreviewBuffer)
  END
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ) OR pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN SELF.SetLastError(TpsErrBlobContext,'Invalid blob read context; current record=' & SELF.CurrentRecord & ' record queue count=' & RECORDS(SELF.DataQ) & ' field number=' & pFieldNo & ' field count=' & RECORDS(SELF.FieldQ))
  END
  GET(SELF.FieldQ,pFieldNo)
  IF ~SELF.FieldQ.IsBlob
    RETURN SELF.SetLastError(TpsErrBlobFieldType,'Field is not a BLOB; field number=' & pFieldNo & ' name=' & CLIP(SELF.FieldQ.ShortName) & ' type=' & CLIP(SELF.FieldQ.TypeName))
  END
  MemoIndex = SELF.FieldQ.MemoIndex
  GET(SELF.DataQ,SELF.CurrentRecord)
  Owner = SELF.DataQ.RecordNumber
  IF ~SELF.MemoIsComplete(Owner,MemoIndex,RawLen)
    RawLen = 0
  END
  IF RawLen = 0
    RETURN SELF.SetLastError(0,'')
  END
  IF RawLen < TpsBlobLenPrefix
    IF SELF.IgnoreErrors
      RETURN SELF.SetLastError(0,'')
    END
    RETURN SELF.SetLastError(TpsErrBlobData,'TPS BLOB is missing its four-byte length header')
  END
  IF pMaxBytes < 0
    pMaxBytes = 0
  END
  CopyLen = RawLen
  IF pMaxBytes < RawLen - TpsBlobLenPrefix
    CopyLen = pMaxBytes + TpsBlobLenPrefix
  END
  Raw &= NEW(STRING(CopyLen))
  IF Raw &= NULL
    RETURN SELF.SetLastError(TpsErrBlobData,'Could not allocate TPS BLOB preview buffer; byte count=' & CopyLen)
  END
  CopyLen = SELF.CopyMemoRaw(Owner,MemoIndex,Raw,CopyLen)
  IF CopyLen < TpsBlobLenPrefix
    DISPOSE(Raw)
    IF SELF.IgnoreErrors
      RETURN SELF.SetLastError(0,'')
    END
    RETURN SELF.SetLastError(TpsErrBlobData,'TPS BLOB is missing its four-byte length header')
  END
  BlobLen = SELF.ReadLeLong(Raw,0)
  Avail = RawLen - TpsBlobLenPrefix
  IF BlobLen > Avail
    IF SELF.IgnoreErrors
      BlobLen = Avail
    ELSE
      DISPOSE(Raw)
      RETURN SELF.SetLastError(TpsErrBlobData,'TPS BLOB declares ' & BlobLen & ' bytes but only ' & Avail & ' are available')
    END
  END
  IF BlobLen < 0
    IF SELF.IgnoreErrors
      BlobLen = Avail
    ELSE
      DISPOSE(Raw)
      RETURN SELF.SetLastError(TpsErrBlobData,'TPS BLOB declares negative length ' & BlobLen)
    END
  END
  pBlobLength = BlobLen
  PreviewLen = BlobLen
  IF PreviewLen > pMaxBytes
    PreviewLen = pMaxBytes
  END
  IF PreviewLen > 0
    SELF.BlobPreviewBuffer &= NEW(STRING(PreviewLen))
    IF SELF.BlobPreviewBuffer &= NULL
      DISPOSE(Raw)
      RETURN SELF.SetLastError(TpsErrBlobData,'Could not allocate TPS BLOB preview result; byte count=' & PreviewLen)
    END
    SELF.BlobPreviewBuffer = Raw[TpsBlobLenPrefix + 1 : TpsBlobLenPrefix + PreviewLen]
  END
  DISPOSE(Raw)
  RETURN SELF.SetLastError(0,'')

TpsParserType.Construct PROCEDURE
  CODE
  SELF.Src &= NULL
  SELF.WorkPage &= NULL
  SELF.ReturnBuffer &= NULL
  SELF.BlobPreviewBuffer &= NULL
  SELF.LastErrorText &= NULL
  SELF.DataQ &= NEW(TpsDataQueue)
  SELF.MemoQ &= NEW(TpsMemoQueue)
  SELF.TableDefQ &= NEW(TpsTableDefQueue)
  SELF.TableNameQ &= NEW(TpsTableNameQueue)
  SELF.FieldQ &= NEW(TpsFieldQueue)

TpsParserType.Destruct  PROCEDURE
  CODE
  SELF.Kill()
  IF ~SELF.DataQ &= NULL
    DISPOSE(SELF.DataQ)
  END
  IF ~SELF.MemoQ &= NULL
    DISPOSE(SELF.MemoQ)
  END
  IF ~SELF.TableDefQ &= NULL
    DISPOSE(SELF.TableDefQ)
  END
  IF ~SELF.TableNameQ &= NULL
    DISPOSE(SELF.TableNameQ)
  END
  IF ~SELF.FieldQ &= NULL
    DISPOSE(SELF.FieldQ)
  END

TpsParserType.RollbackData PROCEDURE(LONG pKeep)
I                           LONG
  CODE
  LOOP I = RECORDS(SELF.DataQ) TO pKeep + 1 BY -1
    GET(SELF.DataQ,I)
    IF ~SELF.DataQ.Payload &= NULL
      DISPOSE(SELF.DataQ.Payload)
    END
    DELETE(SELF.DataQ)
  END

TpsParserType.RollbackMemos PROCEDURE(LONG pKeep)
I                            LONG
  CODE
  LOOP I = RECORDS(SELF.MemoQ) TO pKeep + 1 BY -1
    GET(SELF.MemoQ,I)
    IF ~SELF.MemoQ.Payload &= NULL
      DISPOSE(SELF.MemoQ.Payload)
    END
    DELETE(SELF.MemoQ)
  END

TpsParserType.RollbackTableDefs PROCEDURE(LONG pKeep)
I                                LONG
  CODE
  LOOP I = RECORDS(SELF.TableDefQ) TO pKeep + 1 BY -1
    GET(SELF.TableDefQ,I)
    IF ~SELF.TableDefQ.Payload &= NULL
      DISPOSE(SELF.TableDefQ.Payload)
    END
    DELETE(SELF.TableDefQ)
  END

TpsParserType.RollbackTableNames PROCEDURE(LONG pKeep)
I                                 LONG
  CODE
  LOOP I = RECORDS(SELF.TableNameQ) TO pKeep + 1 BY -1
    GET(SELF.TableNameQ,I)
    IF ~SELF.TableNameQ.Name &= NULL
      DISPOSE(SELF.TableNameQ.Name)
    END
    DELETE(SELF.TableNameQ)
  END

TpsParserType.FreeData PROCEDURE
  CODE
  SELF.RollbackData(0)

TpsParserType.FreeMemos PROCEDURE
  CODE
  SELF.RollbackMemos(0)

TpsParserType.FreeTableDefs PROCEDURE
  CODE
  SELF.RollbackTableDefs(0)

TpsParserType.FreeTableNames PROCEDURE
  CODE
  SELF.RollbackTableNames(0)

TpsParserType.FreeFields PROCEDURE
I                         LONG
  CODE
  LOOP I = RECORDS(SELF.FieldQ) TO 1 BY -1
    GET(SELF.FieldQ,I)
    IF ~SELF.FieldQ.Name &= NULL
      DISPOSE(SELF.FieldQ.Name)
    END
    IF ~SELF.FieldQ.ShortName &= NULL
      DISPOSE(SELF.FieldQ.ShortName)
    END
    DELETE(SELF.FieldQ)
  END

TpsParserType.SetReturnBuffer PROCEDURE(*STRING pData,LONG pPos,LONG pLen)
  CODE
  IF ~SELF.ReturnBuffer &= NULL
    DISPOSE(SELF.ReturnBuffer)
  END
  IF pPos < 0 OR pLen < 1 OR pPos + pLen > SIZE(pData)
    RETURN ''
  END
  SELF.ReturnBuffer &= NEW(STRING(pLen))
  SELF.ReturnBuffer = pData[pPos + 1 : pPos + pLen]
  RETURN SELF.ReturnBuffer

TpsParserType.TrimFixedString PROCEDURE(*STRING pData,LONG pPos,LONG pLen)
  CODE
  IF pPos < 0 OR pLen < 1 OR pPos + pLen > SIZE(pData)
    RETURN ''
  END
  LOOP WHILE pLen > 0
    IF SELF.ReadByte(pData,pPos + pLen - 1) <> 0 AND SELF.ReadByte(pData,pPos + pLen - 1) <> 32
      BREAK
    END
    pLen -= 1
  END
  RETURN SELF.SetReturnBuffer(pData,pPos,pLen)

TpsParserType.ResolveTableNumber    PROCEDURE(LONG pTableIndex)
I                                     LONG
Count                                 LONG
LastNo                                LONG
TotalLen                              LONG
  CODE
  IF pTableIndex < 1
    RETURN 0
  END
  SORT(SELF.TableDefQ,+SELF.TableDefQ.TableNo,+SELF.TableDefQ.BlockNo)
  Count = 0
  LastNo = -1
  LOOP I = 1 TO RECORDS(SELF.TableDefQ)
    GET(SELF.TableDefQ,I)
    IF SELF.TableDefQ.TableNo <> LastNo
      LastNo = SELF.TableDefQ.TableNo
      IF SELF.TableDefinitionIsComplete(LastNo,TotalLen)
        Count += 1
        IF Count = pTableIndex
          RETURN LastNo
        END
      END
    END
  END
  RETURN 0

TpsParserType.GetTableNameByTableNumber PROCEDURE(LONG pTableNo)
I                                         LONG
ColonPos                                  LONG
NameLen                                   LONG
SavedTable                                LONG
Result                                    LONG
ResultName                                &STRING
NumberText                                STRING(20)
  CODE
  ResultName &= NULL
  IF pTableNo = 0
    RETURN ''
  END
  LOOP I = 1 TO RECORDS(SELF.TableNameQ)
    GET(SELF.TableNameQ,I)
    IF SELF.TableNameQ.TableNo = pTableNo AND ~SELF.TableNameQ.Name &= NULL
      NameLen = SIZE(SELF.TableNameQ.Name)
      LOOP WHILE NameLen > 0
        IF SELF.ReadByte(SELF.TableNameQ.Name,NameLen - 1) <> 0 AND SELF.ReadByte(SELF.TableNameQ.Name,NameLen - 1) <> 32
          BREAK
        END
        NameLen -= 1
      END
      IF NameLen > 0
        IF UPPER(SELF.TableNameQ.Name[1 : NameLen]) <> 'UNNAMED'
          IF ~ResultName &= NULL
            DISPOSE(ResultName)
          END
          ResultName &= NEW(STRING(NameLen))
          ResultName = SELF.TableNameQ.Name[1 : NameLen]
        END
      END
    END
  END
  IF ~ResultName &= NULL
    NumberText = SELF.SetReturnBuffer(ResultName,0,SIZE(ResultName))
    DISPOSE(ResultName)
    RETURN SELF.ReturnBuffer
  END
  SavedTable = SELF.CurrentTable
  SELF.CurrentTable = pTableNo
  IF SELF.ParseTableLayout() = 0
    LOOP I = 1 TO RECORDS(SELF.FieldQ)
      GET(SELF.FieldQ,I)
      IF SELF.FieldQ.TableNo = pTableNo
        ColonPos = INSTRING(':',SELF.FieldQ.Name,1,1)
        IF ColonPos > 1
          IF UPPER(SELF.FieldQ.Name[1 : ColonPos - 1]) <> 'UNNAMED'
            ResultName &= NEW(STRING(ColonPos - 1))
            ResultName = SELF.FieldQ.Name[1 : ColonPos - 1]
            BREAK
          END
        END
      END
    END
  END
  SELF.CurrentTable = SavedTable
  IF SavedTable <> 0
    Result = SELF.ParseTableLayout()
  END
  IF ~ResultName &= NULL
    NumberText = SELF.SetReturnBuffer(ResultName,0,SIZE(ResultName))
    DISPOSE(ResultName)
    RETURN SELF.ReturnBuffer
  END
  NumberText = pTableNo
  RETURN CLIP(NumberText)

TpsParserType.LoadSource    PROCEDURE(STRING pFileName)
RawName                       STRING(TpsFileNameMax)
RawFile                       FILE,DRIVER('DOS'),PRE(RAW)
Record                          RECORD
Buffer                            STRING(TpsDosBufferMax)
                                END
                              END
FileSize                      LONG
ReadOfs                       LONG
Fetch                         LONG
  CODE
  RawName = pFileName
  RawFile{PROP:Name} = RawName
  OPEN(RawFile,TpsDosReadMode)
  IF ERRORCODE()
    RETURN SELF.SetLastError(TpsErrSourceOpen,'Could not open source file "' & CLIP(pFileName) & '", ERRORCODE=' & ERRORCODE())
  END
  FileSize = BYTES(RawFile)
  IF FileSize <= 0
    CLOSE(RawFile)
    RETURN SELF.SetLastError(TpsErrSourceEmpty,'Source file is empty: "' & CLIP(pFileName) & '"')
  END
  SELF.SrcLen = FileSize
  IF ~SELF.Src &= NULL
    DISPOSE(SELF.Src)
  END
  SELF.Src &= NEW(STRING(FileSize))
  ReadOfs = 0
  LOOP WHILE ReadOfs < FileSize
    Fetch = SIZE(RAW:Buffer)
    IF Fetch > FileSize - ReadOfs
      Fetch = FileSize - ReadOfs
    END
    GET(RawFile,ReadOfs + 1,Fetch)
    IF ERRORCODE()
      CLOSE(RawFile)
      RETURN SELF.SetLastError(TpsErrSourceRead,'Could not read source file "' & CLIP(pFileName) & '" at offset=' & ReadOfs & ' length=' & Fetch & ', ERRORCODE=' & ERRORCODE())
    END
    SELF.Src[ReadOfs + 1 : ReadOfs + Fetch] = RAW:Buffer[1 : Fetch]
    ReadOfs += Fetch
  END
  CLOSE(RawFile)
  RETURN 0

TpsParserType.DecryptSource PROCEDURE(STRING pOwner)
Key                           STRING(TpsKeySize)
I                             LONG
StartOfs                      LONG
EndOfs                        LONG
Length                        LONG
Result                        LONG
  CODE
  IF SELF.SrcLen < TpsHeaderDecryptLen
    RETURN SELF.SetLastError(TpsErrDecryptTooShort,'Encrypted TPS is too short to decrypt header; bytes=' & SELF.SrcLen)
  END
  CLEAR(Key)
  SELF.BuildOwnerKey(pOwner,Key)
  Result = SELF.DecryptRange(0,TpsHeaderDecryptLen,Key)
  IF Result <> 0
    RETURN SELF.SetLastError(TpsErrDecryptHeaderRange,'Encrypted TPS decrypt failed at header; offset=0 length=' & TpsHeaderDecryptLen)
  END
  IF SELF.ReadLeLong(SELF.Src,0) <> 0
    RETURN SELF.SetLastError(TpsErrDecryptHeaderMarker,'Encrypted TPS decrypt failed; bad owner/password or invalid header marker')
  END
  IF SELF.Slice(SELF.Src,TpsSignatureOffset,TpsSignatureLen) <> 'tOpS'
    RETURN SELF.SetLastError(TpsErrDecryptSignature,'Encrypted TPS decrypt failed; bad owner/password or invalid signature=' & SELF.Slice(SELF.Src,TpsSignatureOffset,TpsSignatureLen))
  END
  LOOP I = 0 TO ((TpsBlockEndTable - TpsBlockStartTable) / 4) - 1
    StartOfs = BSHIFT(SELF.ReadLeLong(SELF.Src,TpsBlockStartTable + (I * 4)),TpsBlockAddrShift) + TpsFirstPageOffset
    EndOfs   = BSHIFT(SELF.ReadLeLong(SELF.Src,TpsBlockEndTable + (I * 4)),TpsBlockAddrShift) + TpsFirstPageOffset
    IF ~((StartOfs = TpsFirstPageOffset AND EndOfs = TpsFirstPageOffset) OR StartOfs >= SELF.SrcLen)
      IF StartOfs < TpsFirstPageOffset OR EndOfs < StartOfs OR EndOfs > SELF.SrcLen
        IF SELF.IgnoreErrors
          CYCLE
        END
        RETURN SELF.SetLastError(TpsErrDecryptDataRange,'Invalid encrypted TPS block range; start=' & StartOfs & ' end=' & EndOfs & ' source bytes=' & SELF.SrcLen)
      END
      Length = EndOfs - StartOfs
      IF Length > 0
        Result = SELF.DecryptRange(StartOfs,Length,Key)
        IF Result <> 0
          IF SELF.IgnoreErrors
            Result = SELF.SetLastError(0,'')
            CYCLE
          END
          RETURN SELF.SetLastError(TpsErrDecryptDataRange,'Encrypted TPS decrypt failed; offset=' & StartOfs & ' length=' & Length)
        END
      END
    END
  END
  RETURN 0

TpsParserType.BuildOwnerKey PROCEDURE(STRING pOwner,*STRING pKey)
I                             LONG
Target                        LONG
Source                        LONG
OwnerLen                      LONG
KeyLen                        LONG
B                             LONG
  CODE
  CLEAR(pKey)
  OwnerLen = LEN(CLIP(pOwner))
  KeyLen = OwnerLen + 1
  LOOP I = 0 TO TpsKeySize - 1
    Target = BAND(I * TpsKeyByteStep,TpsKeyIndexMask)
    Source = SELF.ModLong(I + 1,KeyLen)
    IF Source < OwnerLen
      B = SELF.ReadByte(pOwner,Source)
    ELSE
      B = 0
    END
    pKey[Target + 1] = CHR(BAND(I + B,TpsByteMask))
  END
  SELF.ShuffleKey(pKey)
  SELF.ShuffleKey(pKey)

TpsParserType.ShuffleKey    PROCEDURE(*STRING pKey)
I                             LONG
WordA                         LONG
WordB                         LONG
PosB                          LONG
  CODE
  LOOP I = 0 TO TpsKeyWords - 1
    WordA = SELF.ReadLeLong(pKey,I * 4)
    PosB = BAND(WordA,0FH)
    WordB = SELF.ReadLeLong(pKey,PosB * 4)
    SELF.WriteLeLong(pKey,PosB * 4,WordA + BAND(WordA,WordB))
    SELF.WriteLeLong(pKey,I * 4,BOR(WordA,WordB) + WordA)
  END

TpsParserType.DecryptRange  PROCEDURE(LONG pOffset,LONG pLength,*STRING pKey)
Pos                           LONG
EndPos                        LONG
  CODE
  IF pOffset < 0 OR pLength < 0 OR pOffset + pLength > SELF.SrcLen
    RETURN SELF.SetLastError(TpsErrDecryptRangeBounds,'Decrypt range is outside source; offset=' & pOffset & ' length=' & pLength & ' source bytes=' & SELF.SrcLen)
  END
  IF BAND(pOffset,TpsKeySize - 1) <> 0 OR BAND(pLength,TpsKeySize - 1) <> 0
    RETURN SELF.SetLastError(TpsErrDecryptRangeAlign,'Decrypt range is not 64-byte aligned; offset=' & pOffset & ' length=' & pLength)
  END
  Pos = pOffset
  EndPos = pOffset + pLength
  LOOP WHILE Pos < EndPos
    SELF.DecryptBlock64(Pos,pKey)
    Pos += TpsKeySize
  END
  RETURN 0

TpsParserType.DecryptBlock64    PROCEDURE(LONG pOffset,*STRING pKey)
I                                 LONG
PosB                              LONG
KeyA                              LONG
NotKeyA                           LONG
Data1                             LONG
Data2                             LONG
  CODE
  I = TpsKeyWords - 1
  LOOP WHILE I >= 0
    KeyA = SELF.ReadLeLong(pKey,I * 4)
    PosB = BAND(KeyA,0FH)
    Data1 = SELF.ReadLeLong(SELF.Src,pOffset + (I * 4)) - KeyA
    Data2 = SELF.ReadLeLong(SELF.Src,pOffset + (PosB * 4)) - KeyA
    NotKeyA = BXOR(KeyA,TpsWordNotMask)
    SELF.WriteLeLong(SELF.Src,pOffset + (I * 4),BOR(BAND(Data1,KeyA),BAND(Data2,NotKeyA)))
    SELF.WriteLeLong(SELF.Src,pOffset + (PosB * 4),BOR(BAND(Data2,KeyA),BAND(Data1,NotKeyA)))
    I -= 1
  END

TpsParserType.ParseTps  PROCEDURE
Result                    LONG
  CODE
  SELF.FreeData()
  SELF.FreeMemos()
  SELF.FreeTableDefs()
  SELF.FreeTableNames()
  SELF.FreeFields()
  Result = SELF.ValidateHeader()
  IF Result <> 0
    RETURN Result
  END
  SELF.ParsePass = TpsPassMetadata
  Result = SELF.ParseAllBlocks()
  IF Result <> 0
    RETURN Result
  END
  IF SELF.Tables() = 0
    RETURN SELF.SetLastError(TpsErrTableDefMissing,'No complete table definitions found')
  END
  SELF.ParsePass = TpsPassContent
  Result = SELF.ParseAllBlocks()
  IF Result <> 0
    RETURN Result
  END
  SELF.ParsePass = 0
  RETURN 0

TpsParserType.ValidateHeader PROCEDURE
HeaderSize                LONG
TopSpeed                  STRING(TpsSignatureLen)
  CODE
  IF SELF.SrcLen < TpsMinHeaderLen
    RETURN SELF.SetLastError(TpsErrHeaderTooShort,'Source is too short to be a TPS file; bytes=' & SELF.SrcLen)
  END
  IF SELF.ReadLeLong(SELF.Src,0) <> 0
    RETURN SELF.SetLastError(TpsErrHeaderMarker,'Invalid TPS header marker at offset=0; value=' & SELF.ReadLeLong(SELF.Src,0))
  END
  HeaderSize = SELF.ReadLeShort(SELF.Src,4)
  IF HeaderSize < TpsMinHeaderLen OR HeaderSize > SELF.SrcLen
    RETURN SELF.SetLastError(TpsErrHeaderSize,'Invalid TPS header size=' & HeaderSize & '; source bytes=' & SELF.SrcLen)
  END
  TopSpeed = SELF.Slice(SELF.Src,TpsSignatureOffset,TpsSignatureLen)
  IF TopSpeed <> 'tOpS'
    RETURN SELF.SetLastError(TpsErrHeaderSignature,'Invalid TPS signature at offset=' & TpsSignatureOffset & '; value=' & TopSpeed)
  END
  RETURN 0

TpsParserType.ParseAllBlocks PROCEDURE
I                         LONG
StartRef                  LONG
EndRef                    LONG
StartOfs                  LONG
EndOfs                    LONG
Result                    LONG
  CODE
  LOOP I = 0 TO ((TpsBlockEndTable - TpsBlockStartTable) / 4) - 1
    StartRef = SELF.ReadLeLong(SELF.Src,TpsBlockStartTable + (I * 4))
    EndRef = SELF.ReadLeLong(SELF.Src,TpsBlockEndTable + (I * 4))
    IF StartRef < 0 OR EndRef < 0
      IF SELF.IgnoreErrors
        CYCLE
      END
      RETURN SELF.SetLastError(TpsErrBlockRange,'Invalid negative TPS block reference; block=' & I)
    END
    StartOfs = BSHIFT(StartRef,TpsBlockAddrShift) + TpsFirstPageOffset
    EndOfs = BSHIFT(EndRef,TpsBlockAddrShift) + TpsFirstPageOffset
    IF StartOfs = TpsFirstPageOffset AND EndOfs = TpsFirstPageOffset
      CYCLE
    END
    IF StartOfs < TpsFirstPageOffset OR EndOfs < StartOfs OR EndOfs > SELF.SrcLen
      IF SELF.IgnoreErrors
        CYCLE
      END
      RETURN SELF.SetLastError(TpsErrBlockRange,'Invalid TPS block range; start=' & StartOfs & ' end=' & EndOfs & ' source bytes=' & SELF.SrcLen)
    END
    IF StartOfs < SELF.SrcLen
      Result = SELF.ParseBlock(StartOfs,EndOfs)
      IF Result <> 0 AND ~SELF.IgnoreErrors
        RETURN Result
      END
    END
  END
  RETURN 0

TpsParserType.ParseBlock    PROCEDURE(LONG pStart,LONG pEnd)
Pos                           LONG
Addr                          LONG
PageSize                      LONG
Result                        LONG
  CODE
  IF pStart < TpsFirstPageOffset OR pEnd < pStart OR pEnd > SELF.SrcLen
    RETURN SELF.SetLastError(TpsErrBlockRange,'Invalid TPS block range; start=' & pStart & ' end=' & pEnd)
  END
  Pos = pStart
  LOOP WHILE Pos < pEnd AND Pos <= pEnd - 6
    IF SELF.ReadLeLong(SELF.Src,Pos) = Pos
      PageSize = SELF.ReadLeShort(SELF.Src,Pos + 4)
      IF PageSize < TpsPageHeaderLen OR Pos + PageSize > pEnd OR Pos + PageSize > SELF.SrcLen
        IF ~SELF.IgnoreErrors
          RETURN SELF.SetLastError(TpsErrPageInvalid,'Invalid TPS page size=' & PageSize & ' at offset=' & Pos)
        END
        Pos += TpsPageScanStep
        CYCLE
      END
      IF SELF.IsCompletePage(Pos,PageSize,pEnd)
        IF SELF.ParsePage(Pos,pEnd) = 0
          Pos += PageSize
        ELSE
          IF ~SELF.IgnoreErrors
            RETURN SELF.GetErrorCode()
          END
          Result = SELF.SetLastError(0,'')
          Pos += TpsPageScanStep
        END
      ELSE
        Pos += TpsPageScanStep
      END
    ELSE
      Pos += TpsPageScanStep
    END
    IF BAND(Pos,TpsPageScanStep - 1) <> 0
      Pos = BAND(Pos,TpsAlignMask) + TpsPageScanStep
    END
    LOOP WHILE Pos < pEnd AND Pos < SELF.SrcLen - 4
      Addr = SELF.ReadLeLong(SELF.Src,Pos)
      IF Addr = Pos
        BREAK
      END
      Pos += TpsPageScanStep
    END
  END
  RETURN 0

TpsParserType.IsCompletePage    PROCEDURE(LONG pPos,LONG pPageSize,LONG pEnd)
Ofs                               LONG
Addr                              LONG
  CODE
  IF pPageSize < TpsPageHeaderLen OR pPos + pPageSize > pEnd OR pPos + pPageSize > SELF.SrcLen
    RETURN FALSE
  END
  Ofs = TpsPageScanStep
  LOOP WHILE Ofs < pPageSize AND pPos + Ofs <= pEnd - 4
    Addr = SELF.ReadLeLong(SELF.Src,pPos + Ofs)
    IF Addr = pPos + Ofs
      RETURN FALSE
    END
    Ofs += TpsPageScanStep
  END
  RETURN TRUE

TpsParserType.ParsePage PROCEDURE(LONG pPos,LONG pEnd)
PageSize                  LONG
PageUncompressedSize      LONG
RecCount                  LONG
Flags                     LONG
CompressedStart           LONG
CompressedLen             LONG
KeepData                  LONG
KeepMemos                 LONG
KeepDefs                  LONG
KeepNames                 LONG
Result                    LONG
  CODE
  PageSize = SELF.ReadLeShort(SELF.Src,pPos + 4)
  IF PageSize < TpsPageHeaderLen OR pPos + PageSize > pEnd OR pPos + PageSize > SELF.SrcLen
    RETURN SELF.SetLastError(TpsErrPageInvalid,'Invalid TPS page size=' & PageSize & ' at offset=' & pPos)
  END
  PageUncompressedSize = SELF.ReadLeShort(SELF.Src,pPos + 6)
  RecCount   = SELF.ReadLeShort(SELF.Src,pPos + 10)
  Flags      = SELF.ReadByte(SELF.Src,pPos + 12)
  IF Flags <> 0
    RETURN 0
  END
  CompressedStart = pPos + TpsPageHeaderLen
  CompressedLen   = PageSize - TpsPageHeaderLen
  IF SELF.BuildWorkPage(CompressedStart,CompressedLen,PageSize,PageUncompressedSize,Flags)
    RETURN SELF.SetLastError(TpsErrRleInvalid,'Invalid TPS page compression at offset=' & pPos)
  END
  KeepData = RECORDS(SELF.DataQ)
  KeepMemos = RECORDS(SELF.MemoQ)
  KeepDefs = RECORDS(SELF.TableDefQ)
  KeepNames = RECORDS(SELF.TableNameQ)
  Result = SELF.ParseRecords(SELF.WorkPage,SELF.WorkPageLen,RecCount)
  IF Result <> 0
    SELF.RollbackData(KeepData)
    SELF.RollbackMemos(KeepMemos)
    SELF.RollbackTableDefs(KeepDefs)
    SELF.RollbackTableNames(KeepNames)
    RETURN Result
  END
  RETURN 0

TpsParserType.BuildWorkPage PROCEDURE(LONG pCompressedStart,LONG pCompressedLen,LONG pPageSize,LONG pPageSizeUncompressed,LONG pFlags)
ExpectedLen                   LONG
CompressedPos                 LONG
Skip                          LONG
ByteToRepeat                  LONG
Repeats                       LONG
I                             LONG
  CODE
  IF ~SELF.WorkPage &= NULL
    DISPOSE(SELF.WorkPage)
  END
  ExpectedLen = pPageSizeUncompressed - TpsPageHeaderLen
  IF ExpectedLen < 0
    RETURN 1
  END
  SELF.WorkPageLen = 0
  IF pPageSize <> pPageSizeUncompressed AND pFlags = 0
    SELF.WorkPage &= NEW(STRING(CHOOSE(ExpectedLen > 0,ExpectedLen,1)))
    CompressedPos = 0
    LOOP WHILE CompressedPos < pCompressedLen - 1
      IF SELF.DecodeRleCount(pCompressedStart,pCompressedLen,CompressedPos,Skip)
        RETURN 1
      END
      IF Skip = 0
        RETURN 1
      END
      IF SELF.WorkPageLen + Skip > ExpectedLen OR CompressedPos + Skip > pCompressedLen
        RETURN 1
      END
      SELF.WorkPage[SELF.WorkPageLen + 1 : SELF.WorkPageLen + Skip] = SELF.Src[pCompressedStart + CompressedPos + 1 : pCompressedStart + CompressedPos + Skip]
      SELF.WorkPageLen += Skip
      CompressedPos += Skip
      IF ~(CompressedPos > pCompressedLen - 1)
        CompressedPos -= 1
        ByteToRepeat = SELF.ReadByte(SELF.Src,pCompressedStart + CompressedPos)
        CompressedPos += 1
        IF SELF.DecodeRleCount(pCompressedStart,pCompressedLen,CompressedPos,Repeats)
          RETURN 1
        END
        IF SELF.WorkPageLen + Repeats > ExpectedLen
          RETURN 1
        END
        LOOP I = 1 TO Repeats
          SELF.WorkPage[SELF.WorkPageLen + I] = CHR(ByteToRepeat)
        END
        SELF.WorkPageLen += Repeats
      END
    END
  ELSE
    SELF.WorkPage &= NEW(STRING(CHOOSE(pCompressedLen > 0,pCompressedLen,1)))
    IF pCompressedLen > 0
      SELF.WorkPage[1 : pCompressedLen] = SELF.Src[pCompressedStart + 1 : pCompressedStart + pCompressedLen]
    END
    SELF.WorkPageLen = pCompressedLen
  END
  IF pPageSize <> pPageSizeUncompressed AND SELF.WorkPageLen <> ExpectedLen
    RETURN 1
  END
  RETURN 0

TpsParserType.DecodeRleCount    PROCEDURE(LONG pCompressedStart,LONG pCompressedLen,*LONG pCompressedPos,*LONG pCount)
Msb                               LONG
Lsb                               LONG
Shift                             LONG
  CODE
  pCount = 0
  IF pCompressedPos >= pCompressedLen
    RETURN 1
  END
  pCount = SELF.ReadByte(SELF.Src,pCompressedStart + pCompressedPos)
  pCompressedPos += 1
  IF pCount = 0
    RETURN 1
  END
  IF pCount > TpsRleExtended
    IF pCompressedPos >= pCompressedLen
      RETURN 1
    END
    Msb = SELF.ReadByte(SELF.Src,pCompressedStart + pCompressedPos)
    pCompressedPos += 1
    Lsb = BAND(pCount,TpsRleExtended)
    Shift = TpsRleBase * BAND(Msb,1)
    pCount = BAND(BSHIFT(Msb,7),0FF00H) + Lsb + Shift
  END
  RETURN 0

TpsParserType.ParseRecords  PROCEDURE(*STRING pData,LONG pLen,LONG pRecordCount)
Pos                           LONG
Count                         LONG
Flags                         LONG
RecordLen                     LONG
HeaderLen                     LONG
CopyLen                       LONG
NeedLen                       LONG
Prev                          &STRING
Cur                           &STRING
PrevLen                       LONG
PrevHdr                       LONG
Result                        LONG
  CODE
  Pos = 0
  Count = 0
  PrevLen = 0
  PrevHdr = 0
  Prev &= NULL
  IF pRecordCount > 0
    IF pLen < 5
      RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'TPS page record stream is too short')
    END
    Flags = SELF.ReadByte(pData,0)
    IF BAND(Flags,TpsFlagRecLen + TpsFlagHeaderLen) <> TpsFlagRecLen + TpsFlagHeaderLen
      RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'First TPS record does not contain record and header lengths')
    END
  END
  LOOP WHILE Pos < pLen - 1 AND Count < pRecordCount
    Flags = SELF.ReadByte(pData,Pos)
    Pos += 1
    IF BAND(Flags,TpsFlagRecLen) <> 0
      IF Pos + 2 > pLen
        Result = TpsErrRecordPageInvalid
        BREAK
      END
      RecordLen = SELF.ReadLeShort(pData,Pos)
      Pos += 2
    ELSE
      RecordLen = PrevLen
    END
    IF BAND(Flags,TpsFlagHeaderLen) <> 0
      IF Pos + 2 > pLen
        Result = TpsErrRecordPageInvalid
        BREAK
      END
      HeaderLen = SELF.ReadLeShort(pData,Pos)
      Pos += 2
    ELSE
      HeaderLen = PrevHdr
    END
    CopyLen = BAND(Flags,TpsFlagCopyLen)
    IF CopyLen > 0 AND Prev &= NULL
      Result = TpsErrRecordPageInvalid
      BREAK
    END
    IF RecordLen < 0 OR RecordLen < CopyLen OR CopyLen > PrevLen OR HeaderLen < 0 OR HeaderLen > RecordLen OR Pos + (RecordLen - CopyLen) > pLen
      Result = TpsErrRecordPageInvalid
      BREAK
    END
    IF RecordLen = 0
      IF ~Prev &= NULL
        DISPOSE(Prev)
      END
      Prev &= NULL
      PrevLen = 0
      PrevHdr = HeaderLen
      Count += 1
      CYCLE
    END
    Cur &= NEW(STRING(RecordLen))
    IF CopyLen > 0
      Cur[1 : CopyLen] = Prev[1 : CopyLen]
    END
    NeedLen = RecordLen - CopyLen
    IF NeedLen > 0
      Cur[CopyLen + 1 : RecordLen] = pData[Pos + 1 : Pos + NeedLen]
    END
    Pos += NeedLen
    Result = SELF.ProcessRecord(Cur,RecordLen,HeaderLen)
    IF Result <> 0
      DISPOSE(Cur)
      BREAK
    END
    IF ~Prev &= NULL
      DISPOSE(Prev)
    END
    Prev &= Cur
    PrevLen = RecordLen
    PrevHdr = HeaderLen
    Count += 1
  END
  IF ~Prev &= NULL
    DISPOSE(Prev)
  END
  IF Result <> 0 OR Count <> pRecordCount
    IF Result = 0
      Result = TpsErrRecordPageInvalid
    END
    RETURN SELF.SetLastError(Result,'TPS page declares ' & pRecordCount & ' records but ' & Count & ' were decoded')
  END
  RETURN 0

TpsParserType.ProcessRecord PROCEDURE(*STRING pRecord,LONG pRecordLen,LONG pHeaderLen)
RecordType                    LONG
TableNo                       LONG
RecNo                         LONG
Owner                         LONG
MemoIndex                     LONG
Seq                           LONG
PayloadLen                    LONG
BlockNo                       LONG
NameLen                       LONG
Payload                       &STRING
  CODE
  Payload &= NULL
  IF pHeaderLen < 1 OR pRecordLen < pHeaderLen
    RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'Invalid TPS record/header length')
  END
  IF SELF.ReadByte(pRecord,0) = TpsRecTableName
    IF SELF.ParsePass = TpsPassMetadata
      IF pRecordLen < pHeaderLen + 4
        RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'Invalid TPS table-name record')
      END
      CLEAR(SELF.TableNameQ)
      SELF.TableNameQ.TableNo = SELF.ReadBeLong(pRecord,pHeaderLen)
      NameLen = pHeaderLen - 1
      IF NameLen > 0
        SELF.TableNameQ.Name &= NEW(STRING(NameLen))
        SELF.TableNameQ.Name = pRecord[2 : NameLen + 1]
      END
      SELF.Arrival += 1
      SELF.TableNameQ.Arrival = SELF.Arrival
      ADD(SELF.TableNameQ)
      IF ERRORCODE()
        IF ~SELF.TableNameQ.Name &= NULL
          DISPOSE(SELF.TableNameQ.Name)
        END
        RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS table name')
      END
    END
    RETURN 0
  END
  IF pHeaderLen < 5
    RETURN 0
  END
  RecordType = SELF.ReadByte(pRecord,4)
  TableNo = SELF.ReadBeLong(pRecord,0)
  CASE RecordType
    OF TpsRecData
      IF SELF.ParsePass <> TpsPassContent
        RETURN 0
      END
      IF pHeaderLen < 9
        RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'Invalid TPS data-record header length=' & pHeaderLen)
      END
      RecNo = SELF.ReadBeLong(pRecord,5)
      PayloadLen = pRecordLen - pHeaderLen
      IF PayloadLen > 0
        Payload &= NEW(STRING(PayloadLen))
        Payload = pRecord[pHeaderLen + 1 : pRecordLen]
        IF SELF.ValidateRecordPayload(TableNo,Payload,PayloadLen)
          DISPOSE(Payload)
          RETURN SELF.GetErrorCode()
        END
        CLEAR(SELF.DataQ)
        SELF.DataQ.TableNo = TableNo
        SELF.DataQ.RecordNumber = RecNo
        SELF.DataQ.PayloadLen = PayloadLen
        SELF.DataQ.Payload &= Payload
        ADD(SELF.DataQ)
        IF ERRORCODE()
          DISPOSE(SELF.DataQ.Payload)
          RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS data record')
        END
      END
    OF TpsRecMemo
      IF SELF.ParsePass <> TpsPassContent
        RETURN 0
      END
      IF pHeaderLen < 12
        RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'Invalid TPS MEMO-record header length=' & pHeaderLen)
      END
      Owner = SELF.ReadBeLong(pRecord,5)
      MemoIndex = SELF.ReadByte(pRecord,9)
      Seq = SELF.ReadBeShort(pRecord,10)
      PayloadLen = pRecordLen - pHeaderLen
      IF PayloadLen > 0
        CLEAR(SELF.MemoQ)
        SELF.MemoQ.TableNo = TableNo
        SELF.MemoQ.Owner = Owner
        SELF.MemoQ.MemoIndex = MemoIndex
        SELF.MemoQ.Sequence = Seq
        SELF.MemoQ.DataLen = PayloadLen
        SELF.MemoQ.Payload &= NEW(STRING(PayloadLen))
        SELF.MemoQ.Payload = pRecord[pHeaderLen + 1 : pRecordLen]
        SELF.Arrival += 1
        SELF.MemoQ.Arrival = SELF.Arrival
        ADD(SELF.MemoQ)
        IF ERRORCODE()
          DISPOSE(SELF.MemoQ.Payload)
          RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS MEMO fragment')
        END
      END
    OF TpsRecTableDef
      IF SELF.ParsePass <> TpsPassMetadata
        RETURN 0
      END
      IF pHeaderLen < 7
        RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'Invalid TPS table-definition header length=' & pHeaderLen)
      END
      BlockNo = SELF.ReadLeShort(pRecord,5)
      PayloadLen = pRecordLen - pHeaderLen
      IF PayloadLen > 0
        CLEAR(SELF.TableDefQ)
        SELF.TableDefQ.TableNo = TableNo
        SELF.TableDefQ.BlockNo = BlockNo
        SELF.TableDefQ.DataLen = PayloadLen
        SELF.TableDefQ.Payload &= NEW(STRING(PayloadLen))
        SELF.TableDefQ.Payload = pRecord[pHeaderLen + 1 : pRecordLen]
        SELF.Arrival += 1
        SELF.TableDefQ.Arrival = SELF.Arrival
        ADD(SELF.TableDefQ)
        IF ERRORCODE()
          DISPOSE(SELF.TableDefQ.Payload)
          RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS table-definition fragment')
        END
      END
  END
  RETURN 0

TpsParserType.TableDefinitionIsComplete PROCEDURE(LONG pTableNo,*LONG pTotalLen)
I                                         LONG
J                                         LONG
Expected                                  LONG
Last                                      LONG
Found                                     BYTE
  CODE
  pTotalLen = 0
  Expected = 0
  SORT(SELF.TableDefQ,+SELF.TableDefQ.TableNo,+SELF.TableDefQ.BlockNo,+SELF.TableDefQ.Arrival)
  I = 1
  LOOP WHILE I <= RECORDS(SELF.TableDefQ)
    GET(SELF.TableDefQ,I)
    IF SELF.TableDefQ.TableNo <> pTableNo
      I += 1
      CYCLE
    END
    IF SELF.TableDefQ.BlockNo <> Expected
      RETURN FALSE
    END
    Found = TRUE
    Last = I
    J = I + 1
    LOOP WHILE J <= RECORDS(SELF.TableDefQ)
      GET(SELF.TableDefQ,J)
      IF SELF.TableDefQ.TableNo <> pTableNo OR SELF.TableDefQ.BlockNo <> Expected
        BREAK
      END
      Last = J
      J += 1
    END
    GET(SELF.TableDefQ,Last)
    pTotalLen += SELF.TableDefQ.DataLen
    Expected += 1
    I = J
  END
  RETURN Found

TpsParserType.ParseTableLayout  PROCEDURE
I                                 LONG
J                                 LONG
Last                              LONG
Expected                          LONG
Pos                               LONG
TotalLen                          LONG
Def                               &STRING
DriverVer                         LONG
RecordLen                         LONG
NrFields                          LONG
NrMemos                           LONG
NrIndexes                         LONG
FieldType                         LONG
FieldName                         &STRING
MemoName                          &STRING
NameLen                           LONG
ShortLen                          LONG
ColonPos                          LONG
Elements                          LONG
FieldLen                          LONG
FieldFlags                        LONG
IndexNo                           LONG
MemoLen                           LONG
MemoFlags                         LONG
Result                            LONG
  CODE
  Def &= NULL
  FieldName &= NULL
  MemoName &= NULL
  SELF.FreeFields()
  IF RECORDS(SELF.TableDefQ) = 0
    RETURN SELF.SetLastError(TpsErrTableDefMissing,'No table definitions found')
  END
  IF SELF.CurrentTable = 0
    SELF.CurrentTable = SELF.ResolveTableNumber(1)
  END
  IF ~SELF.TableDefinitionIsComplete(SELF.CurrentTable,TotalLen) OR TotalLen < 10
    RETURN SELF.SetLastError(TpsErrTableDefIncomplete,'Incomplete table definition for table=' & SELF.CurrentTable & '; bytes=' & TotalLen)
  END
  Def &= NEW(STRING(TotalLen))
  Pos = 0
  Expected = 0
  I = 1
  LOOP WHILE I <= RECORDS(SELF.TableDefQ)
    GET(SELF.TableDefQ,I)
    IF SELF.TableDefQ.TableNo = SELF.CurrentTable AND SELF.TableDefQ.BlockNo = Expected
      Last = I
      J = I + 1
      LOOP WHILE J <= RECORDS(SELF.TableDefQ)
        GET(SELF.TableDefQ,J)
        IF SELF.TableDefQ.TableNo <> SELF.CurrentTable OR SELF.TableDefQ.BlockNo <> Expected
          BREAK
        END
        Last = J
        J += 1
      END
      GET(SELF.TableDefQ,Last)
      Def[Pos + 1 : Pos + SELF.TableDefQ.DataLen] = SELF.TableDefQ.Payload
      Pos += SELF.TableDefQ.DataLen
      Expected += 1
      I = J
    ELSE
      I += 1
    END
  END
  Pos = 0
  DriverVer = SELF.ReadLeShort(Def,Pos); Pos += 2
  RecordLen = SELF.ReadLeShort(Def,Pos); Pos += 2
  NrFields  = SELF.ReadLeShort(Def,Pos); Pos += 2
  NrMemos   = SELF.ReadLeShort(Def,Pos); Pos += 2
  NrIndexes = SELF.ReadLeShort(Def,Pos); Pos += 2
  LOOP I = 1 TO NrFields
    IF Pos + 3 > TotalLen
      DISPOSE(Def)
      RETURN SELF.SetLastError(TpsErrFieldDefHeader,'Incomplete field definition header; table=' & SELF.CurrentTable & ' field=' & I & ' offset=' & Pos & ' total=' & TotalLen)
    END
    FieldType = SELF.ReadByte(Def,Pos); Pos += 1
    FieldName &= NULL
    CLEAR(SELF.FieldQ)
    SELF.FieldQ.TableNo = SELF.CurrentTable
    SELF.FieldQ.FieldNo = I
    SELF.FieldQ.FieldType = FieldType
    SELF.FieldQ.Offset = SELF.ReadLeShort(Def,Pos); Pos += 2
    NameLen = SELF.ReadZeroString(Def,TotalLen,Pos)
    IF NameLen < 0
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrFieldDefBody,'Unterminated field name; table=' & SELF.CurrentTable & ' field=' & I)
    END
    IF NameLen > 0
      FieldName &= NEW(STRING(NameLen))
      FieldName = SELF.ReturnBuffer
    ELSE
      FieldName &= NEW(STRING(1))
      CLEAR(FieldName)
    END
    IF Pos + 8 > TotalLen
      Result = SELF.SetLastError(TpsErrFieldDefBody,'Incomplete field definition body; table=' & SELF.CurrentTable & ' field=' & I & ' name=' & CLIP(FieldName) & ' offset=' & Pos & ' total=' & TotalLen)
      DISPOSE(FieldName)
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN TpsErrFieldDefBody
    END
    SELF.FieldQ.Name &= FieldName
    ShortLen = LEN(SELF.StripTablePrefix(FieldName))
    IF ShortLen > 0
      SELF.FieldQ.ShortName &= NEW(STRING(ShortLen))
      SELF.FieldQ.ShortName = SELF.ReturnBuffer
    ELSE
      SELF.FieldQ.ShortName &= NEW(STRING(1))
      CLEAR(SELF.FieldQ.ShortName)
    END
    Elements = SELF.ReadLeShort(Def,Pos); Pos += 2
    FieldLen = SELF.ReadLeShort(Def,Pos); Pos += 2
    FieldFlags = SELF.ReadLeShort(Def,Pos); Pos += 2
    IndexNo = SELF.ReadLeShort(Def,Pos); Pos += 2
    IF Elements < 1 OR FieldLen < 1 OR FieldLen % Elements <> 0
      IF ~SELF.FieldQ.Name &= NULL
        DISPOSE(SELF.FieldQ.Name)
      END
      IF ~SELF.FieldQ.ShortName &= NULL
        DISPOSE(SELF.FieldQ.ShortName)
      END
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Invalid field dimensions; table=' & SELF.CurrentTable & ' field=' & I & ' elements=' & Elements & ' length=' & FieldLen)
    END
    SELF.FieldQ.Elements = Elements
    SELF.FieldQ.Length = FieldLen
    CASE FieldType
      OF TpsFieldByte
        SELF.FieldQ.TypeName = 'BYTE'
      OF TpsFieldShort
        SELF.FieldQ.TypeName = 'SHORT'
      OF TpsFieldUShort
        SELF.FieldQ.TypeName = 'USHORT'
      OF TpsFieldDate
        SELF.FieldQ.TypeName = 'DATE'
      OF TpsFieldTime
        SELF.FieldQ.TypeName = 'TIME'
      OF TpsFieldLong
        SELF.FieldQ.TypeName = 'LONG'
      OF TpsFieldULong
        SELF.FieldQ.TypeName = 'ULONG'
      OF TpsFieldFloat
        SELF.FieldQ.TypeName = 'SREAL'
      OF TpsFieldDouble
        SELF.FieldQ.TypeName = 'REAL'
      OF TpsFieldBcd
        SELF.FieldQ.TypeName = 'DECIMAL'
      OF TpsFieldString
        SELF.FieldQ.TypeName = 'STRING'
      OF TpsFieldCString
        SELF.FieldQ.TypeName = 'CSTRING'
      OF TpsFieldPString
        SELF.FieldQ.TypeName = 'PSTRING'
      OF TpsFieldGroup
        SELF.FieldQ.TypeName = 'GROUP'
      ELSE
        SELF.FieldQ.TypeName = 'UNKNOWN'
    END
    CASE FieldType
      OF TpsFieldBcd
        IF Pos + 2 > TotalLen
          Result = SELF.SetLastError(TpsErrBcdMetadata,'Incomplete BCD metadata; table=' & SELF.CurrentTable & ' field=' & I & ' name=' & CLIP(FieldName) & ' offset=' & Pos & ' total=' & TotalLen)
          IF ~SELF.FieldQ.Name &= NULL
            DISPOSE(SELF.FieldQ.Name)
          END
          IF ~SELF.FieldQ.ShortName &= NULL
            DISPOSE(SELF.FieldQ.ShortName)
          END
          DISPOSE(Def)
          SELF.FreeFields()
          RETURN TpsErrBcdMetadata
        END
        SELF.FieldQ.BcdDigitsAfterDecimal = SELF.ReadByte(Def,Pos); Pos += 1
        SELF.FieldQ.BcdLengthOfElement = SELF.ReadByte(Def,Pos); Pos += 1
    END
    ADD(SELF.FieldQ)
    IF ERRORCODE()
      IF ~SELF.FieldQ.Name &= NULL
        DISPOSE(SELF.FieldQ.Name)
      END
      IF ~SELF.FieldQ.ShortName &= NULL
        DISPOSE(SELF.FieldQ.ShortName)
      END
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS field definition')
    END
    CASE FieldType
      OF TpsFieldString OROF TpsFieldCString OROF TpsFieldPString
        IF Pos + 2 > TotalLen
          Result = SELF.SetLastError(TpsErrStringMetadata,'Incomplete string metadata; table=' & SELF.CurrentTable & ' field=' & I & ' name=' & CLIP(FieldName) & ' offset=' & Pos & ' total=' & TotalLen)
          DISPOSE(Def)
          SELF.FreeFields()
          RETURN TpsErrStringMetadata
        END
        Pos += 2
        NameLen = SELF.ReadZeroString(Def,TotalLen,Pos)
        IF NameLen < 0
          DISPOSE(Def)
          SELF.FreeFields()
          RETURN SELF.SetLastError(TpsErrStringExternalName,'Unterminated string external name; table=' & SELF.CurrentTable & ' field=' & I)
        END
        IF NameLen = 0
          IF Pos + 1 > TotalLen
            DISPOSE(Def)
            SELF.FreeFields()
            RETURN SELF.SetLastError(TpsErrStringExternalName,'Incomplete string external-name marker; table=' & SELF.CurrentTable & ' field=' & I & ' offset=' & Pos & ' total=' & TotalLen)
          END
          Pos += 1
        END
    END
  END
  LOOP I = 0 TO NrMemos - 1
    NameLen = SELF.ReadZeroString(Def,TotalLen,Pos)
    IF NameLen < 0
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrMemoExternalName,'Unterminated MEMO external name; table=' & SELF.CurrentTable & ' memo=' & I)
    END
    IF NameLen = 0
      IF Pos + 1 > TotalLen
        DISPOSE(Def)
        SELF.FreeFields()
        RETURN SELF.SetLastError(TpsErrMemoExternalName,'Incomplete memo external-name marker; table=' & SELF.CurrentTable & ' memo=' & I & ' offset=' & Pos & ' total=' & TotalLen)
      END
      Pos += 1
    END
    NameLen = SELF.ReadZeroString(Def,TotalLen,Pos)
    IF NameLen < 0
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrMemoDef,'Unterminated MEMO name; table=' & SELF.CurrentTable & ' memo=' & I)
    END
    IF NameLen > 0
      MemoName &= NEW(STRING(NameLen))
      MemoName = SELF.ReturnBuffer
    ELSE
      MemoName &= NEW(STRING(1))
      CLEAR(MemoName)
    END
    IF Pos + 4 > TotalLen
      Result = SELF.SetLastError(TpsErrMemoDef,'Incomplete memo definition; table=' & SELF.CurrentTable & ' memo=' & I & ' name=' & CLIP(MemoName) & ' offset=' & Pos & ' total=' & TotalLen)
      DISPOSE(MemoName)
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN TpsErrMemoDef
    END
    MemoLen = SELF.ReadLeShort(Def,Pos); Pos += 2
    MemoFlags = SELF.ReadLeShort(Def,Pos); Pos += 2
    CLEAR(SELF.FieldQ)
    SELF.FieldQ.TableNo = SELF.CurrentTable
    SELF.FieldQ.FieldNo = NrFields + I + 1
    SELF.FieldQ.Name &= MemoName
    ShortLen = LEN(SELF.StripTablePrefix(MemoName))
    IF ShortLen > 0
      SELF.FieldQ.ShortName &= NEW(STRING(ShortLen))
      SELF.FieldQ.ShortName = SELF.ReturnBuffer
    ELSE
      SELF.FieldQ.ShortName &= NEW(STRING(1))
      CLEAR(SELF.FieldQ.ShortName)
    END
    SELF.FieldQ.FieldType = TpsMemoFieldType
    SELF.FieldQ.MemoIndex = I
    SELF.FieldQ.IsMemo = CHOOSE(BAND(MemoFlags,TpsBlobFlag) = 0,1,0)
    SELF.FieldQ.IsBlob = CHOOSE(BAND(MemoFlags,TpsBlobFlag) <> 0,1,0)
    SELF.FieldQ.TypeName = CHOOSE(SELF.FieldQ.IsBlob,'BLOB','MEMO')
    ADD(SELF.FieldQ)
    IF ERRORCODE()
      IF ~SELF.FieldQ.Name &= NULL
        DISPOSE(SELF.FieldQ.Name)
      END
      IF ~SELF.FieldQ.ShortName &= NULL
        DISPOSE(SELF.FieldQ.ShortName)
      END
      DISPOSE(Def)
      SELF.FreeFields()
      RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS MEMO definition')
    END
  END
  DISPOSE(Def)
  IF RECORDS(SELF.FieldQ) = 0
    RETURN SELF.SetLastError(TpsErrFieldDefMissing,'No fields found in table definition; table=' & SELF.CurrentTable)
  END
  RETURN 0

TpsParserType.ValidateRecordPayload PROCEDURE(LONG pTableNo,*STRING pData,LONG pLen)
I                                    LONG
J                                    LONG
E                                    LONG
ByteIndex                            LONG
ElementLen                           LONG
Offset                               LONG
GroupOffset                          LONG
GroupEnd                             LONG
Value                                LONG
Y                                    LONG
M                                    LONG
D                                    LONG
H                                    LONG
S                                    LONG
Hundredths                           LONG
Declared                             LONG
B                                    LONG
Result                               LONG
  CODE
  SELF.CurrentTable = pTableNo
  Result = SELF.ParseTableLayout()
  IF Result <> 0
    RETURN Result
  END
  LOOP I = 1 TO RECORDS(SELF.FieldQ)
    GET(SELF.FieldQ,I)
    IF SELF.FieldQ.IsMemo OR SELF.FieldQ.IsBlob
      CYCLE
    END
    IF SELF.FieldQ.Elements < 1 OR SELF.FieldQ.Length < 1 OR SELF.FieldQ.Length % SELF.FieldQ.Elements <> 0
      RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Invalid field dimensions; table=' & pTableNo & ' field=' & CLIP(SELF.FieldQ.Name))
    END
    IF SELF.FieldQ.Offset < 0 OR SELF.FieldQ.Offset + SELF.FieldQ.Length > pLen
      RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Field range exceeds record; table=' & pTableNo & ' field=' & CLIP(SELF.FieldQ.Name) & ' offset=' & SELF.FieldQ.Offset & ' length=' & SELF.FieldQ.Length & ' record=' & pLen)
    END
    ElementLen = SELF.FieldQ.Length / SELF.FieldQ.Elements
    CASE SELF.FieldQ.FieldType
      OF TpsFieldByte
        IF ElementLen <> 1
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'BYTE field has invalid width; field=' & CLIP(SELF.FieldQ.Name) & ' width=' & ElementLen)
        END
      OF TpsFieldShort OROF TpsFieldUShort
        IF ElementLen <> 2
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'SHORT field has invalid width; field=' & CLIP(SELF.FieldQ.Name) & ' width=' & ElementLen)
        END
      OF TpsFieldDate OROF TpsFieldTime OROF TpsFieldLong OROF TpsFieldULong OROF TpsFieldFloat
        IF ElementLen <> 4
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Four-byte field has invalid width; field=' & CLIP(SELF.FieldQ.Name) & ' width=' & ElementLen)
        END
      OF TpsFieldDouble
        IF ElementLen <> 8
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'REAL field has invalid width; field=' & CLIP(SELF.FieldQ.Name) & ' width=' & ElementLen)
        END
      OF TpsFieldBcd
        IF SELF.FieldQ.BcdLengthOfElement <> ElementLen
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'DECIMAL storage width does not match metadata; field=' & CLIP(SELF.FieldQ.Name) & ' width=' & ElementLen & ' metadata=' & SELF.FieldQ.BcdLengthOfElement)
        END
        IF SELF.FieldQ.BcdDigitsAfterDecimal > (ElementLen * 2) - 1
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'DECIMAL scale exceeds stored digits; field=' & CLIP(SELF.FieldQ.Name))
        END
        LOOP E = 0 TO SELF.FieldQ.Elements - 1
          Offset = SELF.FieldQ.Offset + (E * ElementLen)
          LOOP ByteIndex = 0 TO ElementLen - 1
            B = SELF.ReadByte(pData,Offset + ByteIndex)
            IF BAND(B,0FH) > 9 OR (ByteIndex > 0 AND BSHIFT(B,-4) > 9)
              RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'DECIMAL contains a non-decimal BCD digit; field=' & CLIP(SELF.FieldQ.Name))
            END
          END
        END
      OF TpsFieldString OROF TpsFieldCString OROF TpsFieldGroup
        ! The complete fixed-width bytes are valid data.
      OF TpsFieldPString
        LOOP E = 0 TO SELF.FieldQ.Elements - 1
          Offset = SELF.FieldQ.Offset + (E * ElementLen)
          Declared = SELF.ReadByte(pData,Offset)
          IF Declared > ElementLen - 1
            RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'PSTRING length exceeds field width; field=' & CLIP(SELF.FieldQ.Name) & ' declared=' & Declared & ' available=' & ElementLen - 1)
          END
        END
      ELSE
        RETURN SELF.SetLastError(TpsErrFieldTypeUnsupported,'Unsupported TPS field type=' & SELF.FieldQ.FieldType & ' field=' & CLIP(SELF.FieldQ.Name))
    END
    IF SELF.FieldQ.FieldType = TpsFieldDate
      LOOP E = 0 TO SELF.FieldQ.Elements - 1
        Offset = SELF.FieldQ.Offset + (E * ElementLen)
        Value = SELF.ReadLeLong(pData,Offset)
        IF Value <> 0
          Y = BSHIFT(BAND(Value,0FFFF0000H),-16)
          M = BSHIFT(BAND(Value,0000FF00H),-8)
          D = BAND(Value,000000FFH)
          IF Y < 1801 OR M < 1 OR M > 12 OR D < 1 OR D > 31 OR MONTH(DATE(M,D,Y)) <> M OR DAY(DATE(M,D,Y)) <> D
            RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Invalid TPS date; field=' & CLIP(SELF.FieldQ.Name) & ' value=' & Y & '-' & M & '-' & D)
          END
        END
      END
    ELSIF SELF.FieldQ.FieldType = TpsFieldTime
      LOOP E = 0 TO SELF.FieldQ.Elements - 1
        Offset = SELF.FieldQ.Offset + (E * ElementLen)
        Value = SELF.ReadLeLong(pData,Offset)
        H = BSHIFT(BAND(Value,0FF000000H),-24)
        M = BSHIFT(BAND(Value,00FF0000H),-16)
        S = BSHIFT(BAND(Value,0000FF00H),-8)
        Hundredths = BAND(Value,000000FFH)
        IF H > 23 OR M > 59 OR S > 59 OR Hundredths > 99
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Invalid TPS time; field=' & CLIP(SELF.FieldQ.Name))
        END
      END
    END
  END
  LOOP I = 1 TO RECORDS(SELF.FieldQ)
    GET(SELF.FieldQ,I)
    IF SELF.FieldQ.FieldType <> TpsFieldGroup OR SELF.FieldQ.IsMemo OR SELF.FieldQ.IsBlob
      CYCLE
    END
    GroupOffset = SELF.FieldQ.Offset
    GroupEnd = GroupOffset + (SELF.FieldQ.Length / SELF.FieldQ.Elements)
    LOOP J = 1 TO RECORDS(SELF.FieldQ)
      IF J = I
        CYCLE
      END
      GET(SELF.FieldQ,J)
      IF SELF.FieldQ.IsMemo OR SELF.FieldQ.IsBlob
        CYCLE
      END
      IF SELF.FieldQ.Offset >= GroupOffset AND SELF.FieldQ.Offset < GroupEnd
        IF SELF.FieldQ.Offset + SELF.FieldQ.Length > GroupEnd
          RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Field extends outside GROUP prototype; table=' & pTableNo & ' field=' & CLIP(SELF.FieldQ.Name) & ' group offset=' & GroupOffset & ' group end=' & GroupEnd)
        END
      END
    END
  END
  RETURN 0

TpsParserType.ReadZeroString    PROCEDURE(*STRING pData,LONG pLen,*LONG pPos)
Start                             LONG
LenOut                            LONG
B                                 LONG
  CODE
  IF ~SELF.ReturnBuffer &= NULL
    DISPOSE(SELF.ReturnBuffer)
  END
  Start = pPos
  LenOut = 0
  LOOP WHILE pPos < pLen
    B = SELF.ReadByte(pData,pPos)
    pPos += 1
    IF B = 0
      IF LenOut > 0
        SELF.ReturnBuffer &= NEW(STRING(LenOut))
        SELF.ReturnBuffer = pData[Start + 1 : Start + LenOut]
      END
      RETURN LenOut
    END
    LenOut += 1
  END
  RETURN -1

TpsParserType.StripTablePrefix  PROCEDURE(STRING pName)
Idx                               LONG
NameLen                           LONG
  CODE
  NameLen = LEN(CLIP(pName))
  Idx = INSTRING(':',pName,1,1)
  IF Idx > 0 AND Idx < NameLen
    RETURN SELF.SetReturnBuffer(pName,Idx,NameLen - Idx)
  END
  RETURN SELF.SetReturnBuffer(pName,0,NameLen)

TpsParserType.ResolveFieldValue PROCEDURE(LONG pFieldNo,LONG pDimension,*LONG pOffset,*LONG pLength)
ElementLen                        LONG
  CODE
  pOffset = 0
  pLength = 0
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ) OR pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN TRUE
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.IsMemo OR SELF.FieldQ.IsBlob
    RETURN TRUE
  END
  IF SELF.FieldQ.Elements > 1
    IF pDimension < 1 OR pDimension > SELF.FieldQ.Elements
      RETURN TRUE
    END
    ElementLen = SELF.FieldQ.Length / SELF.FieldQ.Elements
    pOffset = SELF.FieldQ.Offset + ((pDimension - 1) * ElementLen)
    pLength = ElementLen
  ELSE
    pOffset = SELF.FieldQ.Offset
    pLength = SELF.FieldQ.Length
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  IF pOffset + pLength > SELF.DataQ.PayloadLen
    RETURN TRUE
  END
  RETURN FALSE

TpsParserType.CompareMemoKey    PROCEDURE(LONG pIndex,LONG pOwner,LONG pMemoIndex)
  CODE
  GET(SELF.MemoQ,pIndex)
  IF SELF.MemoQ.TableNo < SELF.CurrentTable
    RETURN -1
  END
  IF SELF.MemoQ.TableNo > SELF.CurrentTable
    RETURN 1
  END
  IF SELF.MemoQ.Owner < pOwner
    RETURN -1
  END
  IF SELF.MemoQ.Owner > pOwner
    RETURN 1
  END
  IF SELF.MemoQ.MemoIndex < pMemoIndex
    RETURN -1
  END
  IF SELF.MemoQ.MemoIndex > pMemoIndex
    RETURN 1
  END
  RETURN 0

TpsParserType.FindFirstMemoChunk    PROCEDURE(LONG pOwner,LONG pMemoIndex)
First                                 LONG
Last                                  LONG
Mid                                   LONG
Cmp                                   LONG
Found                                 LONG
  CODE
  First = 1
  Last = RECORDS(SELF.MemoQ)
  Found = 0
  LOOP WHILE First <= Last
    Mid = First + ((Last - First) / 2)
    Cmp = SELF.CompareMemoKey(Mid,pOwner,pMemoIndex)
    IF Cmp < 0
      First = Mid + 1
    ELSE
      IF Cmp = 0
        Found = Mid
      END
      Last = Mid - 1
    END
  END
  RETURN Found

TpsParserType.MemoRawLength PROCEDURE(LONG pOwner,LONG pMemoIndex)
RawLen                        LONG
Complete                      BYTE
  CODE
  Complete = SELF.MemoIsComplete(pOwner,pMemoIndex,RawLen)
  RETURN RawLen

TpsParserType.MemoIsComplete PROCEDURE(LONG pOwner,LONG pMemoIndex,*LONG pRawLen)
I                              LONG
J                              LONG
Last                           LONG
Expected                       LONG
Found                          BYTE
  CODE
  pRawLen = 0
  SORT(SELF.MemoQ,+SELF.MemoQ.TableNo,+SELF.MemoQ.Owner,+SELF.MemoQ.MemoIndex,+SELF.MemoQ.Sequence,+SELF.MemoQ.Arrival)
  I = SELF.FindFirstMemoChunk(pOwner,pMemoIndex)
  LOOP WHILE I > 0 AND I <= RECORDS(SELF.MemoQ)
    GET(SELF.MemoQ,I)
    IF SELF.MemoQ.TableNo <> SELF.CurrentTable OR SELF.MemoQ.Owner <> pOwner OR SELF.MemoQ.MemoIndex <> pMemoIndex
      BREAK
    END
    IF SELF.MemoQ.Sequence <> Expected
      RETURN FALSE
    END
    Found = TRUE
    Last = I
    J = I + 1
    LOOP WHILE J <= RECORDS(SELF.MemoQ)
      GET(SELF.MemoQ,J)
      IF SELF.MemoQ.TableNo <> SELF.CurrentTable OR SELF.MemoQ.Owner <> pOwner OR SELF.MemoQ.MemoIndex <> pMemoIndex OR SELF.MemoQ.Sequence <> Expected
        BREAK
      END
      Last = J
      J += 1
    END
    GET(SELF.MemoQ,Last)
    pRawLen += SELF.MemoQ.DataLen
    Expected += 1
    I = J
  END
  RETURN Found

TpsParserType.CopyMemoRaw   PROCEDURE(LONG pOwner,LONG pMemoIndex,*STRING pRaw,LONG pMaxLen)
I                             LONG
J                             LONG
Last                          LONG
Expected                      LONG
RawLen                        LONG
CopyLen                       LONG
CompleteLen                   LONG
  CODE
  RawLen = 0
  IF pMaxLen < 1
    RETURN 0
  END
  IF ~SELF.MemoIsComplete(pOwner,pMemoIndex,CompleteLen)
    RETURN 0
  END
  I = SELF.FindFirstMemoChunk(pOwner,pMemoIndex)
  LOOP WHILE I > 0 AND I <= RECORDS(SELF.MemoQ)
    GET(SELF.MemoQ,I)
    IF SELF.MemoQ.TableNo <> SELF.CurrentTable OR SELF.MemoQ.Owner <> pOwner OR SELF.MemoQ.MemoIndex <> pMemoIndex
      BREAK
    END
    IF SELF.MemoQ.Sequence <> Expected
      RETURN 0
    END
    Last = I
    J = I + 1
    LOOP WHILE J <= RECORDS(SELF.MemoQ)
      GET(SELF.MemoQ,J)
      IF SELF.MemoQ.TableNo <> SELF.CurrentTable OR SELF.MemoQ.Owner <> pOwner OR SELF.MemoQ.MemoIndex <> pMemoIndex OR SELF.MemoQ.Sequence <> Expected
        BREAK
      END
      Last = J
      J += 1
    END
    GET(SELF.MemoQ,Last)
    IF RawLen < pMaxLen
      CopyLen = SELF.MemoQ.DataLen
      IF CopyLen > pMaxLen - RawLen
        CopyLen = pMaxLen - RawLen
      END
      IF CopyLen > 0
        pRaw[RawLen + 1 : RawLen + CopyLen] = SELF.MemoQ.Payload[1 : CopyLen]
        RawLen += CopyLen
      END
    END
    Expected += 1
    I = J
  END
  RETURN RawLen

TpsParserType.SetLastError  PROCEDURE(LONG pError,STRING pText)
TextLen                       LONG
  CODE
  IF pError = 0
    SELF.LastError = 0
    IF ~SELF.LastErrorText &= NULL
      DISPOSE(SELF.LastErrorText)
    END
    RETURN 0
  END
  IF LEN(CLIP(pText)) <> 0
    IF ~SELF.LastErrorText &= NULL
      DISPOSE(SELF.LastErrorText)
    END
    TextLen = LEN(CLIP(pText))
    SELF.LastErrorText &= NEW(STRING(TextLen))
    SELF.LastErrorText = pText[1 : TextLen]
  ELSIF SELF.LastError <> pError OR SELF.LastErrorText &= NULL
    IF ~SELF.LastErrorText &= NULL
      DISPOSE(SELF.LastErrorText)
    END
    CASE pError
      OF 1
        SELF.LastErrorText &= NEW(STRING(16))
        SELF.LastErrorText = 'TPS parser error'
      ELSE
        pText = 'Clarion file error, ERRORCODE=' & pError
        TextLen = LEN(CLIP(pText))
        SELF.LastErrorText &= NEW(STRING(TextLen))
        SELF.LastErrorText = pText[1 : TextLen]
    END
  END
  SELF.LastError = pError
  RETURN pError

TpsParserType.ReadByte  PROCEDURE(*STRING pData,LONG pPos)
  CODE
  IF pPos < 0 OR pPos >= SIZE(pData)
    RETURN 0
  END
  RETURN VAL(pData[pPos + 1])

TpsParserType.ReadLeShort   PROCEDURE(*STRING pData,LONG pPos)
  CODE
  RETURN SELF.ReadByte(pData,pPos) + BSHIFT(SELF.ReadByte(pData,pPos + 1),8)

TpsParserType.ReadBeShort   PROCEDURE(*STRING pData,LONG pPos)
  CODE
  RETURN SELF.ReadByte(pData,pPos + 1) + BSHIFT(SELF.ReadByte(pData,pPos),8)

TpsParserType.ReadLeLong    PROCEDURE(*STRING pData,LONG pPos)
V                             LONG
  CODE
  V = SELF.ReadByte(pData,pPos) + BSHIFT(SELF.ReadByte(pData,pPos + 1),8) + BSHIFT(SELF.ReadByte(pData,pPos + 2),16) + BSHIFT(SELF.ReadByte(pData,pPos + 3),24)
  RETURN V

TpsParserType.ReadBeLong    PROCEDURE(*STRING pData,LONG pPos)
V                             LONG
  CODE
  V = SELF.ReadByte(pData,pPos + 3) + BSHIFT(SELF.ReadByte(pData,pPos + 2),8) + BSHIFT(SELF.ReadByte(pData,pPos + 1),16) + BSHIFT(SELF.ReadByte(pData,pPos),24)
  RETURN V

TpsParserType.WriteLeLong   PROCEDURE(*STRING pData,LONG pPos,LONG pValue)
  CODE
  IF pPos < 0 OR pPos + 4 > SIZE(pData)
    RETURN
  END
  pData[pPos + 1] = CHR(BAND(pValue,TpsByteMask))
  pData[pPos + 2] = CHR(BAND(BSHIFT(pValue,-8),TpsByteMask))
  pData[pPos + 3] = CHR(BAND(BSHIFT(pValue,-16),TpsByteMask))
  pData[pPos + 4] = CHR(BAND(BSHIFT(pValue,-24),TpsByteMask))

TpsParserType.ModLong   PROCEDURE(LONG pValue,LONG pDivisor)
Result                    LONG
  CODE
  IF pDivisor <= 0
    RETURN 0
  END
  Result = pValue
  LOOP WHILE Result >= pDivisor
    Result -= pDivisor
  END
  LOOP WHILE Result < 0
    Result += pDivisor
  END
  RETURN Result

TpsParserType.Slice PROCEDURE(*STRING pData,LONG pPos,LONG pLen)
  CODE
  IF pPos < 0 OR pLen < 1
    RETURN ''
  END
  IF pPos + pLen > SIZE(pData)
    pLen = SIZE(pData) - pPos
  END
  IF pLen > 0
    RETURN SELF.SetReturnBuffer(pData,pPos,pLen)
  END
  RETURN ''

TpsParserType.TpsDateToClarion  PROCEDURE(LONG pValue)
Y                                 LONG
M                                 LONG
D                                 LONG
  CODE
  IF pValue = 0
    RETURN 0
  END
  Y = BSHIFT(BAND(pValue,0FFFF0000H),-16)
  M = BSHIFT(BAND(pValue,0000FF00H),-8)
  D = BAND(pValue,000000FFH)
  IF Y < 1801 OR M < 1 OR M > 12 OR D < 1 OR D > 31
    RETURN 0
  END
  RETURN DATE(M,D,Y)

TpsParserType.TpsTimeToClarion  PROCEDURE(LONG pValue)
H                                 LONG
M                                 LONG
S                                 LONG
Hundredths                        LONG
  CODE
  IF pValue = 0
    RETURN 1
  END
  M = BSHIFT(BAND(pValue,00FF0000H),-16)
  H = BSHIFT(BAND(pValue,0FF000000H),-24)
  S = BSHIFT(BAND(pValue,0000FF00H),-8)
  Hundredths = BAND(pValue,000000FFH)
  IF H > 23 OR M > 59 OR S > 59 OR Hundredths > 99
    RETURN 0
  END
  RETURN (H * 60 * 60 * 100) + (M * 60 * 100) + (S * 100) + Hundredths + 1
