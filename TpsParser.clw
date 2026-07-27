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
TpsDamagedMemoSequence EQUATE(-1)

TpsProgressSinkType.Update PROCEDURE(STRING pStage,LONG pCompleted,LONG pTotal)
  CODE

TpsParserType.AllowMissingDefinition PROCEDURE
  CODE
  RETURN FALSE

TpsParserType.Init  PROCEDURE(STRING pFileName)
  CODE
  RETURN SELF.InitCore(pFileName,'',FALSE,FALSE,FALSE)

TpsParserType.Init  PROCEDURE(STRING pFileName,STRING pOwner)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,FALSE,FALSE)

TpsParserType.InitMetadata PROCEDURE(STRING pFileName)
  CODE
  RETURN SELF.InitCore(pFileName,'',FALSE,FALSE,TRUE)

TpsParserType.InitMetadata PROCEDURE(STRING pFileName,STRING pOwner)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,FALSE,TRUE)

TpsParserType.InitRecovering  PROCEDURE(STRING pFileName)
  CODE
  RETURN SELF.InitCore(pFileName,'',FALSE,TRUE,FALSE)

TpsParserType.Init  PROCEDURE(STRING pFileName,STRING pOwner,BYTE pIgnoreErrors)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,pIgnoreErrors,FALSE)

TpsParserType.InitRecovering  PROCEDURE(STRING pFileName,STRING pOwner)
  CODE
  RETURN SELF.InitCore(pFileName,pOwner,TRUE,TRUE,FALSE)

TpsParserType.InitCore PROCEDURE(STRING pFileName,STRING pOwner,BYTE pHasOwner,BYTE pIgnoreErrors,BYTE pMetadataOnly)
Result                LONG
  CODE
  SELF.Kill()
  SELF.LastError = 0
  SELF.IgnoreErrors = pIgnoreErrors
  SELF.SourceEncrypted = FALSE
  SELF.SourceFileName = pFileName
  Result = SELF.LoadSource(pFileName)
  IF Result <> 0
    RETURN Result
  END
  IF pHasOwner
    Result = SELF.ValidateHeader()
    IF Result <> 0
      SELF.SourceEncrypted = TRUE
      Result = SELF.SetLastError(0,'')
      Result = SELF.DecryptSource(pOwner)
      IF Result <> 0
        RETURN Result
      END
    END
  END
  Result = SELF.ParseTps(pMetadataOnly)
  IF Result <> 0
    RETURN Result
  END
  SORT(SELF.TableDefQ,+SELF.TableDefQ.TableNo,+SELF.TableDefQ.BlockNo)
  SORT(SELF.DataQ,+SELF.DataQ.TableNo,+SELF.DataQ.SourceOffset,+SELF.DataQ.Arrival)
  SELF.InvalidateDataRange()
  SELF.EnsureMemoQSorted()
  IF ~SELF.AllowMissingDefinition() OR SELF.Tables() > 0
    Result = SELF.SetTable(0)
    IF Result <> 0
      RETURN Result
    END
  END
  RETURN SELF.SetLastError(0,'')

TpsParserType.Kill  PROCEDURE
  CODE
  SELF.InvalidateMemoChainCache()
  IF ~SELF.BlockRangeQ &= NULL
    FREE(SELF.BlockRangeQ)
  END
  SELF.BlockRangesReady = FALSE
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
  SELF.FreeKeys()
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
  CLEAR(SELF.SourceFileName)
  SELF.IgnoreErrors = FALSE
  SELF.ParsePass = 0
  SELF.Arrival = 0
  SELF.CurrentPageOffset = 0
  SELF.CurrentRecordLength = 0
  SELF.RecoveryIssues = 0
  SELF.SourceEncrypted = FALSE
  SELF.InvalidateDataRange()
  SELF.MemoQDirty = TRUE

TpsParserType.SetProgressSink PROCEDURE(*TpsProgressSinkType pSink)
  CODE
  SELF.ProgressSink &= pSink

TpsParserType.ClearProgressSink PROCEDURE
  CODE
  SELF.ProgressSink &= NULL

TpsParserType.ReportProgress PROCEDURE(STRING pStage,LONG pCompleted,LONG pTotal)
  CODE
  IF SELF.ProgressSink &= NULL
    RETURN
  END
  IF pCompleted < 0
    pCompleted = 0
  END
  IF pTotal < 1
    pTotal = 1
  END
  IF pCompleted > pTotal
    pCompleted = pTotal
  END
  SELF.ProgressSink.Update(pStage,pCompleted,pTotal)

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
    RETURN SELF.SetLastError(TpsErrTableIndex,'That table does not exist in this file. Details: index=' & pTableIndex & ' tables=' & SELF.Tables())
  END
  SELF.InvalidateMemoChainCache()
  SELF.CurrentTable = TableNo
  SELF.CurrentRecord = 0
  Result = SELF.ParseTableLayout()
  IF Result <> 0
    RETURN Result
  END
  RETURN SELF.SetLastError(0,'')

TpsParserType.GetCurrentTableNumber PROCEDURE
  CODE
  RETURN SELF.CurrentTable

TpsParserType.GetRecordLength PROCEDURE
  CODE
  RETURN SELF.CurrentRecordLength

TpsParserType.Records   PROCEDURE
  CODE
  SELF.EnsureDataRange()
  RETURN SELF.DataRangeCount

TpsParserType.Get   PROCEDURE(LONG pRecordNo)
  CODE
  SELF.EnsureDataRange()
  SELF.InvalidateMemoChainCache()
  IF pRecordNo < 1
    SELF.CurrentRecord = 0
    RETURN SELF.SetLastError(TpsErrRecordIndex,'That record does not exist in this table. Details: index=' & pRecordNo)
  END
  IF pRecordNo > SELF.DataRangeCount
    SELF.CurrentRecord = 0
    RETURN SELF.SetLastError(TpsErrRecordNotFound,'That record does not exist in this table. Details: index=' & pRecordNo & ' records=' & SELF.DataRangeCount)
  END
  SELF.CurrentRecord = SELF.DataRangeFirst + pRecordNo - 1
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.SetLastError(0,'')

TpsParserType.Set   PROCEDURE(LONG pRecordNo)
  CODE
  SELF.EnsureDataRange()
  IF pRecordNo = 0
    SELF.InvalidateMemoChainCache()
    SELF.CurrentRecord = 0
    RETURN SELF.SetLastError(0,'')
  END
  RETURN SELF.Get(pRecordNo)

TpsParserType.Next  PROCEDURE
  CODE
  SELF.EnsureDataRange()
  SELF.InvalidateMemoChainCache()
  IF SELF.DataRangeCount < 1
    SELF.CurrentRecord = 0
    RETURN TRUE
  END
  IF SELF.CurrentRecord < SELF.DataRangeFirst OR |
      SELF.CurrentRecord >= SELF.DataRangeFirst + SELF.DataRangeCount
    SELF.CurrentRecord = SELF.DataRangeFirst
  ELSE
    SELF.CurrentRecord += 1
  END
  IF SELF.CurrentRecord >= SELF.DataRangeFirst + SELF.DataRangeCount
    SELF.CurrentRecord = 0
    RETURN TRUE
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN FALSE

TpsParserType.GetCurrentRecordNumber PROCEDURE
  CODE
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ)
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.DataQ.RecordNumber

TpsParserType.GetCurrentRecordOffset PROCEDURE
  CODE
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ)
    RETURN 0
  END
  GET(SELF.DataQ,SELF.CurrentRecord)
  RETURN SELF.DataQ.SourceOffset

TpsParserType.GetRecoveryIssueCount PROCEDURE
  CODE
  RETURN SELF.RecoveryIssues

TpsParserType.GetSourceSize PROCEDURE
  CODE
  RETURN SELF.SrcLen

TpsParserType.GetSourceEncrypted PROCEDURE
  CODE
  RETURN SELF.SourceEncrypted

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

TpsParserType.GetFieldTypeCodeByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.FieldType

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
    Found = SELF.SetLastError(TpsErrFieldAmbiguous,'More than one field has that name. Details: name=' & CLIP(pFieldName) & ' table=' & SELF.CurrentTable)
    RETURN 0
  END
  IF Matches = 1
    RETURN Found
  END
  RETURN 0

TpsParserType.GetFieldOffsetByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.Offset

TpsParserType.GetFieldLengthByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.Length

TpsParserType.GetFieldFlagsByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.Flags

TpsParserType.GetFieldIndexByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.IndexNo

TpsParserType.GetFieldStringMaskByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.StringMask &= NULL
    RETURN ''
  END
  RETURN SELF.FieldQ.StringMask

TpsParserType.GetFieldIsMemoByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN FALSE
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.IsMemo

TpsParserType.GetFieldIsBlobByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN FALSE
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.IsBlob

TpsParserType.GetMemoLengthByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.MemoLength

TpsParserType.GetMemoFlagsByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN 0
  END
  GET(SELF.FieldQ,pFieldNo)
  RETURN SELF.FieldQ.MemoFlags

TpsParserType.GetExternalNameByNumber PROCEDURE(LONG pFieldNo)
  CODE
  IF pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN ''
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.ExternalName &= NULL
    RETURN ''
  END
  RETURN SELF.FieldQ.ExternalName

TpsParserType.Keys PROCEDURE
I                     LONG
Count                 LONG
  CODE
  Count = 0
  LOOP I = 1 TO RECORDS(SELF.KeyQ)
    GET(SELF.KeyQ,I)
    IF SELF.KeyQ.TableNo = SELF.CurrentTable
      Count += 1
    END
  END
  RETURN Count

TpsParserType.GetKeyName PROCEDURE(LONG pKeyNo)
RecordIndex                LONG
  CODE
  RecordIndex = SELF.FindCurrentKeyRecord(pKeyNo)
  IF RecordIndex = 0
    RETURN ''
  END
  GET(SELF.KeyQ,RecordIndex)
  IF SELF.KeyQ.Name &= NULL
    RETURN ''
  END
  RETURN SELF.KeyQ.Name

TpsParserType.GetKeyFlags PROCEDURE(LONG pKeyNo)
RecordIndex                 LONG
  CODE
  RecordIndex = SELF.FindCurrentKeyRecord(pKeyNo)
  IF RecordIndex = 0
    RETURN 0
  END
  GET(SELF.KeyQ,RecordIndex)
  RETURN SELF.KeyQ.Flags

TpsParserType.GetKeyExternalName PROCEDURE(LONG pKeyNo)
RecordIndex                        LONG
  CODE
  RecordIndex = SELF.FindCurrentKeyRecord(pKeyNo)
  IF RecordIndex = 0
    RETURN ''
  END
  GET(SELF.KeyQ,RecordIndex)
  IF SELF.KeyQ.ExternalName &= NULL
    RETURN ''
  END
  RETURN SELF.KeyQ.ExternalName

TpsParserType.GetKeyFieldCount PROCEDURE(LONG pKeyNo)
RecordIndex                      LONG
  CODE
  RecordIndex = SELF.FindCurrentKeyRecord(pKeyNo)
  IF RecordIndex = 0
    RETURN 0
  END
  GET(SELF.KeyQ,RecordIndex)
  RETURN SELF.KeyQ.FieldCount

TpsParserType.GetKeyFieldIndex PROCEDURE(LONG pKeyNo,LONG pRank)
RecordIndex                      LONG
  CODE
  RecordIndex = SELF.FindCurrentKeyFieldRecord(pKeyNo,pRank)
  IF RecordIndex = 0
    RETURN 0
  END
  GET(SELF.KeyFieldQ,RecordIndex)
  RETURN SELF.KeyFieldQ.FieldIndex

TpsParserType.GetKeyFieldAscending PROCEDURE(LONG pKeyNo,LONG pRank)
RecordIndex                          LONG
  CODE
  RecordIndex = SELF.FindCurrentKeyFieldRecord(pKeyNo,pRank)
  IF RecordIndex = 0
    RETURN FALSE
  END
  GET(SELF.KeyFieldQ,RecordIndex)
  RETURN SELF.KeyFieldQ.Ascending

TpsParserType.FindCurrentKeyRecord PROCEDURE(LONG pKeyNo)
I                                    LONG
Count                                LONG
  CODE
  IF pKeyNo < 1
    RETURN 0
  END
  LOOP I = 1 TO RECORDS(SELF.KeyQ)
    GET(SELF.KeyQ,I)
    IF SELF.KeyQ.TableNo = SELF.CurrentTable
      Count += 1
      IF Count = pKeyNo
        RETURN I
      END
    END
  END
  RETURN 0

TpsParserType.FindCurrentKeyFieldRecord PROCEDURE(LONG pKeyNo,LONG pRank)
I                                         LONG
  CODE
  IF pKeyNo < 1 OR pRank < 1
    RETURN 0
  END
  LOOP I = 1 TO RECORDS(SELF.KeyFieldQ)
    GET(SELF.KeyFieldQ,I)
    IF SELF.KeyFieldQ.TableNo = SELF.CurrentTable AND |
        SELF.KeyFieldQ.KeyNo = pKeyNo AND SELF.KeyFieldQ.Rank = pRank
      RETURN I
    END
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
        B = SELF.SetLastError(TpsErrFieldDataInvalid,'A text field in this record has an impossible length. Details: length=' & StrLen & ' available=' & Length - 1)
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
Copied                                LONG
CacheIndex                            LONG
State                                 BYTE
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
  State = SELF.ResolveMemoChain(Owner,MemoIndex,RawLen,CacheIndex)
  IF State <> TpsMemoStateComplete OR RawLen < 1
    RETURN ''
  END
  IF ~SELF.ReturnBuffer &= NULL
    DISPOSE(SELF.ReturnBuffer)
  END
  SELF.ReturnBuffer &= NEW(STRING(RawLen))
  IF SELF.ReturnBuffer &= NULL
    Copied = SELF.SetLastError(TpsErrMemoDef,'There was not enough memory to read the attached text. Details: bytes=' & RawLen)
    RETURN ''
  END
  Copied = SELF.CopyResolvedMemo(CacheIndex,SELF.ReturnBuffer,RawLen)
  IF Copied <> RawLen
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

TpsParserType.GetMemoStateByNumber PROCEDURE(LONG pFieldNo)
Owner                                LONG
MemoIndex                            LONG
RawLen                               LONG
Prefix                               STRING(TpsBlobLenPrefix)
Copied                               LONG
DeclaredLength                       LONG
CacheIndex                           LONG
State                                BYTE
  CODE
  Copied = SELF.SetLastError(0,'')
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ) OR pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN TpsMemoStateEmpty
  END
  GET(SELF.FieldQ,pFieldNo)
  IF ~SELF.FieldQ.IsMemo AND ~SELF.FieldQ.IsBlob
    RETURN TpsMemoStateEmpty
  END
  MemoIndex = SELF.FieldQ.MemoIndex
  GET(SELF.DataQ,SELF.CurrentRecord)
  Owner = SELF.DataQ.RecordNumber
  State = SELF.ResolveMemoChain(Owner,MemoIndex,RawLen,CacheIndex)
  IF State = TpsMemoStateEmpty
    RETURN TpsMemoStateEmpty
  END
  IF State <> TpsMemoStateComplete
    Copied = SELF.SetLastError(TpsErrMemoDef,'Attached text or file data is incomplete.')
    RETURN TpsMemoStateDamaged
  END
  GET(SELF.FieldQ,pFieldNo)
  IF SELF.FieldQ.IsBlob
    IF RawLen < TpsBlobLenPrefix
      Copied = SELF.SetLastError(TpsErrBlobData,'The attached file is shorter than it claims. Details: raw=' & RawLen)
      RETURN TpsMemoStateDamaged
    END
    Copied = SELF.CopyResolvedMemo(CacheIndex,Prefix,TpsBlobLenPrefix)
    IF Copied < TpsBlobLenPrefix
      Copied = SELF.SetLastError(TpsErrBlobData,'The attached file is shorter than it claims. Details: copied=' & Copied & ' raw=' & RawLen)
      RETURN TpsMemoStateDamaged
    END
    DeclaredLength = SELF.ReadLeLong(Prefix,0)
    IF DeclaredLength < 0 OR DeclaredLength > RawLen - TpsBlobLenPrefix
      Copied = SELF.SetLastError(TpsErrBlobData,'The attached file is a different size than it claims. Details: declared=' & DeclaredLength & ' raw=' & RawLen)
      RETURN TpsMemoStateDamaged
    END
  END
  RETURN TpsMemoStateComplete

TpsParserType.GetBlobValueByNumber PROCEDURE(LONG pFieldNo,*LONG pBlobLength)
  CODE
  RETURN SELF.GetBlobPreviewByNumber(pFieldNo,7FFFFFFFH,pBlobLength)

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
CacheIndex                            LONG
State                                 BYTE
  CODE
  pBlobLength = 0
  IF ~SELF.BlobPreviewBuffer &= NULL
    DISPOSE(SELF.BlobPreviewBuffer)
  END
  IF SELF.CurrentRecord < 1 OR SELF.CurrentRecord > RECORDS(SELF.DataQ) OR pFieldNo < 1 OR pFieldNo > RECORDS(SELF.FieldQ)
    RETURN SELF.SetLastError(TpsErrBlobContext,'The attached file could not be read in this context. Details: record=' & SELF.CurrentRecord & ' records=' & RECORDS(SELF.DataQ) & ' field=' & pFieldNo & ' fields=' & RECORDS(SELF.FieldQ))
  END
  GET(SELF.FieldQ,pFieldNo)
  IF ~SELF.FieldQ.IsBlob
    RETURN SELF.SetLastError(TpsErrBlobFieldType,'That field does not hold an attached file. Details: field=' & pFieldNo & ' name=' & CLIP(SELF.FieldQ.ShortName) & ' type=' & CLIP(SELF.FieldQ.TypeName))
  END
  MemoIndex = SELF.FieldQ.MemoIndex
  GET(SELF.DataQ,SELF.CurrentRecord)
  Owner = SELF.DataQ.RecordNumber
  State = SELF.ResolveMemoChain(Owner,MemoIndex,RawLen,CacheIndex)
  IF State = TpsMemoStateEmpty
    RETURN SELF.SetLastError(0,'')
  END
  IF State <> TpsMemoStateComplete
    IF SELF.IgnoreErrors
      RETURN SELF.SetLastError(0,'')
    END
    RETURN SELF.SetLastError(TpsErrBlobData,'Part of the attached file is damaged.')
  END
  IF RawLen = 0
    RETURN SELF.SetLastError(0,'')
  END
  IF RawLen < TpsBlobLenPrefix
    IF SELF.IgnoreErrors
      RETURN SELF.SetLastError(0,'')
    END
    RETURN SELF.SetLastError(TpsErrBlobData,'The attached file has no readable size.')
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
    RETURN SELF.SetLastError(TpsErrBlobData,'There was not enough memory to read the attached file. Details: bytes=' & CopyLen)
  END
  CopyLen = SELF.CopyResolvedMemo(CacheIndex,Raw,CopyLen)
  IF CopyLen < TpsBlobLenPrefix
    DISPOSE(Raw)
    IF SELF.IgnoreErrors
      RETURN SELF.SetLastError(0,'')
    END
    RETURN SELF.SetLastError(TpsErrBlobData,'The attached file has no readable size.')
  END
  BlobLen = SELF.ReadLeLong(Raw,0)
  Avail = RawLen - TpsBlobLenPrefix
  IF BlobLen > Avail
    IF SELF.IgnoreErrors
      BlobLen = Avail
    ELSE
      DISPOSE(Raw)
      RETURN SELF.SetLastError(TpsErrBlobData,'The attached file is truncated. Details: declared=' & BlobLen & ' available=' & Avail)
    END
  END
  IF BlobLen < 0
    IF SELF.IgnoreErrors
      BlobLen = Avail
    ELSE
      DISPOSE(Raw)
      RETURN SELF.SetLastError(TpsErrBlobData,'The attached file has an impossible size. Details: declared=' & BlobLen)
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
      RETURN SELF.SetLastError(TpsErrBlobData,'There was not enough memory to read the attached file. Details: bytes=' & PreviewLen)
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
  CLEAR(SELF.SourceFileName)
  SELF.DataQ &= NEW(TpsDataQueue)
  SELF.MemoQ &= NEW(TpsMemoQueue)
  SELF.MemoChainQ &= NEW(TpsMemoChainQueue)
  SELF.MemoPartQ &= NEW(TpsMemoPartQueue)
  SELF.BlockRangeQ &= NEW(TpsBlockRangeQueue)
  SELF.DataRangeTable = -1
  SELF.ParsedLayoutTable = -1
  SELF.MemoQDirty = TRUE
  SELF.BlockRangesReady = FALSE
  SELF.TableDefQ &= NEW(TpsTableDefQueue)
  SELF.TableNameQ &= NEW(TpsTableNameQueue)
  SELF.FieldQ &= NEW(TpsFieldQueue)
  SELF.KeyQ &= NEW(TpsKeyQueue)
  SELF.KeyFieldQ &= NEW(TpsKeyFieldQueue)

TpsParserType.Destruct  PROCEDURE
  CODE
  SELF.Kill()
  IF ~SELF.DataQ &= NULL
    DISPOSE(SELF.DataQ)
  END
  IF ~SELF.MemoQ &= NULL
    DISPOSE(SELF.MemoQ)
  END
  IF ~SELF.MemoChainQ &= NULL
    DISPOSE(SELF.MemoChainQ)
  END
  IF ~SELF.MemoPartQ &= NULL
    DISPOSE(SELF.MemoPartQ)
  END
  IF ~SELF.BlockRangeQ &= NULL
    DISPOSE(SELF.BlockRangeQ)
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
  IF ~SELF.KeyQ &= NULL
    DISPOSE(SELF.KeyQ)
  END
  IF ~SELF.KeyFieldQ &= NULL
    DISPOSE(SELF.KeyFieldQ)
  END

TpsParserType.RollbackData PROCEDURE(LONG pKeep)
I                           LONG
  CODE
  IF RECORDS(SELF.DataQ) > pKeep
    SELF.InvalidateDataRange()
  END
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
  IF RECORDS(SELF.MemoQ) > pKeep
    SELF.InvalidateMemoChainCache()
    SELF.MemoQDirty = TRUE
  END
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
  SELF.ParsedLayoutTable = -1
  LOOP I = RECORDS(SELF.FieldQ) TO 1 BY -1
    GET(SELF.FieldQ,I)
    IF ~SELF.FieldQ.Name &= NULL
      DISPOSE(SELF.FieldQ.Name)
    END
    IF ~SELF.FieldQ.ShortName &= NULL
      DISPOSE(SELF.FieldQ.ShortName)
    END
    IF ~SELF.FieldQ.StringMask &= NULL
      DISPOSE(SELF.FieldQ.StringMask)
    END
    IF ~SELF.FieldQ.ExternalName &= NULL
      DISPOSE(SELF.FieldQ.ExternalName)
    END
    DELETE(SELF.FieldQ)
  END

TpsParserType.FreeKeys PROCEDURE
I                       LONG
  CODE
  LOOP I = RECORDS(SELF.KeyQ) TO 1 BY -1
    GET(SELF.KeyQ,I)
    IF ~SELF.KeyQ.Name &= NULL
      DISPOSE(SELF.KeyQ.Name)
    END
    IF ~SELF.KeyQ.ExternalName &= NULL
      DISPOSE(SELF.KeyQ.ExternalName)
    END
    DELETE(SELF.KeyQ)
  END
  FREE(SELF.KeyFieldQ)

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
FileTableName                             STRING(TpsFileNameMax)
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
  IF SELF.Tables() = 1
    FileTableName = SELF.GetSourceTableName()
    IF CLIP(FileTableName) <> ''
      RETURN CLIP(FileTableName)
    END
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

TpsParserType.GetSourceTableName PROCEDURE
SourceName                         STRING(TpsFileNameMax)
NameLen                            LONG
PathPos                            LONG
SlashPos                           LONG
DotPos                             LONG
  CODE
  SourceName = CLIP(SELF.SourceFileName)
  NameLen = LEN(CLIP(SourceName))
  IF NameLen = 0
    RETURN ''
  END
  PathPos = INSTRING('\',SourceName,-1,NameLen)
  SlashPos = INSTRING('/',SourceName,-1,NameLen)
  IF SlashPos > PathPos
    PathPos = SlashPos
  END
  IF PathPos > 0
    SourceName = SourceName[PathPos + 1 : NameLen]
  END
  NameLen = LEN(CLIP(SourceName))
  IF NameLen = 0
    RETURN ''
  END
  DotPos = INSTRING('.',SourceName,-1,NameLen)
  IF DotPos > 1
    RETURN SourceName[1 : DotPos - 1]
  ELSIF DotPos = 1
    RETURN ''
  END
  RETURN CLIP(SourceName)

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
    RETURN SELF.SetLastError(TpsErrSourceOpen,'The file could not be opened. Details: ' & CLIP(pFileName) & ', ERRORCODE=' & ERRORCODE())
  END
  FileSize = BYTES(RawFile)
  IF FileSize <= 0
    CLOSE(RawFile)
    RETURN SELF.SetLastError(TpsErrSourceEmpty,'The file is empty. Details: ' & CLIP(pFileName))
  END
  SELF.SrcLen = FileSize
  IF ~SELF.Src &= NULL
    DISPOSE(SELF.Src)
  END
  SELF.Src &= NEW(STRING(FileSize))
  ReadOfs = 0
  SELF.ReportProgress('Loading source',0,FileSize)
  LOOP WHILE ReadOfs < FileSize
    Fetch = SIZE(RAW:Buffer)
    IF Fetch > FileSize - ReadOfs
      Fetch = FileSize - ReadOfs
    END
    GET(RawFile,ReadOfs + 1,Fetch)
    IF ERRORCODE()
      CLOSE(RawFile)
      RETURN SELF.SetLastError(TpsErrSourceRead,'The file could not be read to the end. Details: ' & CLIP(pFileName) & ' offset=' & ReadOfs & ' length=' & Fetch & ' ERRORCODE=' & ERRORCODE())
    END
    SELF.Src[ReadOfs + 1 : ReadOfs + Fetch] = RAW:Buffer[1 : Fetch]
    ReadOfs += Fetch
    SELF.ReportProgress('Loading source',ReadOfs,FileSize)
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
    RETURN SELF.SetLastError(TpsErrDecryptTooShort,'The file is too short to be an encrypted TPS file. Details: bytes=' & SELF.SrcLen)
  END
  SELF.ReportProgress('Decrypting source',0,SELF.SrcLen)
  CLEAR(Key)
  SELF.BuildOwnerKey(pOwner,Key)
  Result = SELF.DecryptRange(0,TpsHeaderDecryptLen,Key)
  IF Result <> 0
    RETURN SELF.SetLastError(TpsErrDecryptHeaderRange,'Wrong owner password, or the header is damaged. Details: offset=0 length=' & TpsHeaderDecryptLen)
  END
  IF SELF.ReadLeLong(SELF.Src,0) <> 0
    RETURN SELF.SetLastError(TpsErrDecryptHeaderMarker,'Wrong owner password, or this is not an encrypted TPS file. Details: header marker mismatch')
  END
  IF SELF.Slice(SELF.Src,TpsSignatureOffset,TpsSignatureLen) <> 'tOpS'
    RETURN SELF.SetLastError(TpsErrDecryptSignature,'Wrong owner password, or this is not an encrypted TPS file. Details: signature=' & SELF.Slice(SELF.Src,TpsSignatureOffset,TpsSignatureLen))
  END
  LOOP I = 0 TO ((TpsBlockEndTable - TpsBlockStartTable) / 4) - 1
    StartOfs = BSHIFT(SELF.ReadLeLong(SELF.Src,TpsBlockStartTable + (I * 4)),TpsBlockAddrShift) + TpsFirstPageOffset
    EndOfs   = BSHIFT(SELF.ReadLeLong(SELF.Src,TpsBlockEndTable + (I * 4)),TpsBlockAddrShift) + TpsFirstPageOffset
    IF ~((StartOfs = TpsFirstPageOffset AND EndOfs = TpsFirstPageOffset) OR StartOfs >= SELF.SrcLen)
      IF StartOfs < TpsFirstPageOffset OR EndOfs < StartOfs OR EndOfs > SELF.SrcLen
        IF SELF.IgnoreErrors
          CYCLE
        END
        RETURN SELF.SetLastError(TpsErrDecryptDataRange,'The encrypted file is damaged. Details: block start=' & StartOfs & ' end=' & EndOfs & ' bytes=' & SELF.SrcLen)
      END
      Length = EndOfs - StartOfs
      IF Length > 0
        Result = SELF.DecryptRange(StartOfs,Length,Key)
        IF Result <> 0
          IF SELF.IgnoreErrors
            Result = SELF.SetLastError(0,'')
            CYCLE
          END
          RETURN SELF.SetLastError(TpsErrDecryptDataRange,'Wrong owner password, or the file is damaged. Details: offset=' & StartOfs & ' length=' & Length)
        END
      END
      SELF.ReportProgress('Decrypting source',EndOfs,SELF.SrcLen)
    END
  END
  SELF.ReportProgress('Decrypting source',SELF.SrcLen,SELF.SrcLen)
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
    RETURN SELF.SetLastError(TpsErrDecryptRangeBounds,'The encrypted file is damaged. Details: range offset=' & pOffset & ' length=' & pLength & ' bytes=' & SELF.SrcLen)
  END
  IF BAND(pOffset,TpsKeySize - 1) <> 0 OR BAND(pLength,TpsKeySize - 1) <> 0
    RETURN SELF.SetLastError(TpsErrDecryptRangeAlign,'The encrypted file is damaged. Details: unaligned range offset=' & pOffset & ' length=' & pLength)
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

TpsParserType.ParseTps  PROCEDURE(BYTE pMetadataOnly)
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
  SELF.ReportProgress('Scanning definitions',0,SELF.SrcLen)
  Result = SELF.ParseAllBlocks()
  IF Result <> 0
    RETURN Result
  END
  SELF.ReportProgress('Scanning definitions',SELF.SrcLen,SELF.SrcLen)
  IF SELF.Tables() = 0
    IF ~SELF.AllowMissingDefinition()
      RETURN SELF.SetLastError(TpsErrTableDefMissing,'This file no longer describes how its records are laid out.')
    END
  END
  IF pMetadataOnly
    SELF.ParsePass = 0
    RETURN 0
  END
  SELF.ParsePass = TpsPassContent
  SELF.ReportProgress('Scanning records and MEMO/BLOB data',0,SELF.SrcLen)
  Result = SELF.ParseAllBlocks()
  IF Result <> 0
    RETURN Result
  END
  SELF.ReportProgress('Scanning records and MEMO/BLOB data',SELF.SrcLen,SELF.SrcLen)
  SELF.ParsePass = 0
  RETURN 0

TpsParserType.ValidateHeader PROCEDURE
HeaderSize                LONG
TopSpeed                  STRING(TpsSignatureLen)
  CODE
  IF SELF.SrcLen < TpsMinHeaderLen
    RETURN SELF.SetLastError(TpsErrHeaderTooShort,'This file is too short to be a TPS file. Details: bytes=' & SELF.SrcLen)
  END
  IF SELF.ReadLeLong(SELF.Src,0) <> 0
    RETURN SELF.SetLastError(TpsErrHeaderMarker,'This is not a TPS file, or it is password-protected. Details: header marker=' & SELF.ReadLeLong(SELF.Src,0))
  END
  HeaderSize = SELF.ReadLeShort(SELF.Src,4)
  IF HeaderSize < TpsMinHeaderLen OR HeaderSize > SELF.SrcLen
    RETURN SELF.SetLastError(TpsErrHeaderSize,'This is not a TPS file, or it is password-protected. Details: header size=' & HeaderSize & ' bytes=' & SELF.SrcLen)
  END
  TopSpeed = SELF.Slice(SELF.Src,TpsSignatureOffset,TpsSignatureLen)
  IF TopSpeed <> 'tOpS'
    RETURN SELF.SetLastError(TpsErrHeaderSignature,'This is not a TPS file. Details: signature=' & TopSpeed)
  END
  RETURN 0

TpsParserType.BuildBlockRangeCache PROCEDURE
I                         LONG
StartRef                  LONG
EndRef                    LONG
StartOfs                  LONG
EndOfs                    LONG
MaxRef                    LONG
CacheError                LONG
  CODE
  IF SELF.BlockRangesReady
    RETURN 0
  END
  FREE(SELF.BlockRangeQ)
  MaxRef = (SELF.SrcLen - TpsFirstPageOffset) / BSHIFT(1,TpsBlockAddrShift)
  LOOP I = 0 TO ((TpsBlockEndTable - TpsBlockStartTable) / 4) - 1
    StartRef = SELF.ReadLeLong(SELF.Src,TpsBlockStartTable + (I * 4))
    EndRef = SELF.ReadLeLong(SELF.Src,TpsBlockEndTable + (I * 4))
    IF StartRef < 0 OR EndRef < 0
      IF SELF.IgnoreErrors
        SELF.RecoveryIssues += 1
        CYCLE
      END
      RETURN SELF.SetLastError(TpsErrBlockRange,'The file structure is damaged. Details: negative block reference block=' & I)
    END
    IF StartRef = 0 AND EndRef = 0
      CYCLE
    END
    IF StartRef > MaxRef OR EndRef > MaxRef OR EndRef < StartRef
      IF SELF.IgnoreErrors
        SELF.RecoveryIssues += 1
        CYCLE
      END
      RETURN SELF.SetLastError(TpsErrBlockRange,'The file structure is damaged. Details: block=' & I & ' start ref=' & StartRef & ' end ref=' & EndRef & ' bytes=' & SELF.SrcLen)
    END
    StartOfs = BSHIFT(StartRef,TpsBlockAddrShift) + TpsFirstPageOffset
    EndOfs = BSHIFT(EndRef,TpsBlockAddrShift) + TpsFirstPageOffset
    CLEAR(SELF.BlockRangeQ)
    SELF.BlockRangeQ.BlockNo = I
    SELF.BlockRangeQ.StartOfs = StartOfs
    SELF.BlockRangeQ.EndOfs = EndOfs
    ADD(SELF.BlockRangeQ)
    IF ERRORCODE()
      CacheError = ERRORCODE()
      FREE(SELF.BlockRangeQ)
      RETURN SELF.SetLastError(CacheError,'Could not cache a validated TPS block range. Details: block=' & I)
    END
  END
  SELF.BlockRangesReady = TRUE
  RETURN 0

TpsParserType.ParseAllBlocks PROCEDURE
I                         LONG
Result                    LONG
  CODE
  Result = SELF.BuildBlockRangeCache()
  IF Result <> 0
    RETURN Result
  END
  LOOP I = 1 TO RECORDS(SELF.BlockRangeQ)
    GET(SELF.BlockRangeQ,I)
    IF SELF.BlockRangeQ.StartOfs < SELF.SrcLen
      Result = SELF.ParseBlock(SELF.BlockRangeQ.StartOfs,SELF.BlockRangeQ.EndOfs)
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
Stage                         STRING(64)
  CODE
  IF pStart < TpsFirstPageOffset OR pEnd < pStart OR pEnd > SELF.SrcLen
    RETURN SELF.SetLastError(TpsErrBlockRange,'The file structure is damaged. Details: block start=' & pStart & ' end=' & pEnd)
  END
  Stage = CHOOSE(SELF.ParsePass = TpsPassMetadata,'Scanning definitions','Scanning records and MEMO/BLOB data')
  Pos = pStart
  LOOP WHILE Pos < pEnd AND Pos <= pEnd - 6
    IF SELF.ReadLeLong(SELF.Src,Pos) = Pos
      PageSize = SELF.ReadLeShort(SELF.Src,Pos + 4)
      IF PageSize < TpsPageHeaderLen OR Pos + PageSize > pEnd OR Pos + PageSize > SELF.SrcLen
        IF ~SELF.IgnoreErrors
          RETURN SELF.SetLastError(TpsErrPageInvalid,'A page of the file is damaged. Details: page size=' & PageSize & ' at offset=' & Pos)
        END
        SELF.RecoveryIssues += 1
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
          SELF.RecoveryIssues += 1
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
    SELF.ReportProgress(Stage,Pos,SELF.SrcLen)
  END
  RETURN 0

TpsParserType.IsCompletePage    PROCEDURE(LONG pPos,LONG pPageSize,LONG pEnd)
Ofs                               LONG
Addr                              LONG
NestedPos                         LONG
NestedPageSize                    LONG
  CODE
  IF pPageSize < TpsPageHeaderLen OR pPos + pPageSize > pEnd OR pPos + pPageSize > SELF.SrcLen
    RETURN FALSE
  END
  Ofs = TpsPageScanStep
  LOOP WHILE Ofs < pPageSize AND pPos + Ofs <= pEnd - 4
    NestedPos = pPos + Ofs
    Addr = SELF.ReadLeLong(SELF.Src,NestedPos)
    IF Addr = NestedPos AND NestedPos <= pEnd - 6 AND NestedPos <= SELF.SrcLen - 6
      NestedPageSize = SELF.ReadLeShort(SELF.Src,NestedPos + 4)
      IF NestedPageSize >= TpsPageHeaderLen AND |
          NestedPageSize <= pEnd - NestedPos AND |
          NestedPageSize <= SELF.SrcLen - NestedPos
        RETURN FALSE
      END
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
    RETURN SELF.SetLastError(TpsErrPageInvalid,'A page of the file is damaged. Details: page size=' & PageSize & ' at offset=' & pPos)
  END
  PageUncompressedSize = SELF.ReadLeShort(SELF.Src,pPos + 6)
  RecCount   = SELF.ReadLeShort(SELF.Src,pPos + 10)
  Flags      = SELF.ReadByte(SELF.Src,pPos + 12)
  SELF.CurrentPageOffset = pPos
  IF Flags <> 0
    RETURN 0
  END
  CompressedStart = pPos + TpsPageHeaderLen
  CompressedLen   = PageSize - TpsPageHeaderLen
  IF SELF.BuildWorkPage(CompressedStart,CompressedLen,PageSize,PageUncompressedSize,Flags)
    RETURN SELF.SetLastError(TpsErrRleInvalid,'A compressed page of the file is damaged. Details: offset=' & pPos)
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
      RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'A page of the file is truncated.')
    END
    Flags = SELF.ReadByte(pData,0)
    IF BAND(Flags,TpsFlagRecLen + TpsFlagHeaderLen) <> TpsFlagRecLen + TpsFlagHeaderLen
      RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'A page of the file is damaged. Details: first record has no length header')
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
  IF Count = pRecordCount AND Pos < pLen AND ~Prev &= NULL AND PrevLen >= 12 AND |
      SELF.ReadByte(Prev,4) = TpsRecMemo AND RECORDS(SELF.MemoQ) > 0
    GET(SELF.MemoQ,RECORDS(SELF.MemoQ))
    IF SELF.MemoQ.TableNo = SELF.ReadBeLong(Prev,0) AND |
        SELF.MemoQ.Owner = SELF.ReadBeLong(Prev,5) AND |
        SELF.MemoQ.MemoIndex = SELF.ReadByte(Prev,9) AND |
        SELF.MemoQ.Sequence = SELF.ReadBeShort(Prev,10)
      SELF.MemoQ.Sequence = TpsDamagedMemoSequence
      PUT(SELF.MemoQ)
      SELF.MemoQDirty = TRUE
    END
  END
  IF ~Prev &= NULL
    DISPOSE(Prev)
  END
  IF Result <> 0 OR Count <> pRecordCount
    IF Result = 0
      Result = TpsErrRecordPageInvalid
    END
    RETURN SELF.SetLastError(Result,'A page holds fewer records than it claims. Details: declared=' & pRecordCount & ' decoded=' & Count)
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
TotalLen                      LONG
Payload                       &STRING
  CODE
  Payload &= NULL
  IF pHeaderLen < 1 OR pRecordLen < pHeaderLen
    RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'A record in this file has an impossible length.')
  END
  IF SELF.ReadByte(pRecord,0) = TpsRecTableName
    IF SELF.ParsePass = TpsPassMetadata
      IF pRecordLen < pHeaderLen + 4
        RETURN SELF.SetLastError(TpsErrRecordPageInvalid,'A table name in this file is damaged.')
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
        IF SELF.TableDefinitionIsComplete(TableNo,TotalLen)
          IF SELF.ValidateRecordPayload(TableNo,Payload,PayloadLen)
            DISPOSE(Payload)
            RETURN SELF.GetErrorCode()
          END
        ELSIF ~SELF.AllowMissingDefinition()
          DISPOSE(Payload)
          RETURN SELF.SetLastError(TpsErrTableDefMissing,'No complete table definition for data table=' & TableNo)
        END
        CLEAR(SELF.DataQ)
        SELF.DataQ.TableNo = TableNo
        SELF.DataQ.RecordNumber = RecNo
        SELF.DataQ.PayloadLen = PayloadLen
        SELF.DataQ.Payload &= Payload
        SELF.Arrival += 1
        SELF.DataQ.SourceOffset = SELF.CurrentPageOffset
        SELF.DataQ.Arrival = SELF.Arrival
        ADD(SELF.DataQ)
        IF ERRORCODE()
          DISPOSE(SELF.DataQ.Payload)
          RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS data record')
        END
        SELF.InvalidateDataRange()
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
        SELF.MemoQDirty = TRUE
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
RecordLen                         LONG
NrFields                          LONG
NrMemos                           LONG
NrIndexes                         LONG
Result                            LONG
  CODE
  IF SELF.ParsedLayoutTable = SELF.CurrentTable AND RECORDS(SELF.FieldQ) > 0
    RETURN 0
  END
  Def &= NULL
  SELF.FreeFields()
  SELF.FreeKeys()
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
  Pos = 2
  RecordLen = SELF.ReadLeShort(Def,Pos); Pos += 2
  SELF.CurrentRecordLength = RecordLen
  NrFields  = SELF.ReadLeShort(Def,Pos); Pos += 2
  NrMemos   = SELF.ReadLeShort(Def,Pos); Pos += 2
  NrIndexes = SELF.ReadLeShort(Def,Pos); Pos += 2
  Result = SELF.ParseFieldDefinitions(Def,TotalLen,Pos,NrFields)
  IF Result = 0
    Result = SELF.ParseMemoDefinitions(Def,TotalLen,Pos,NrMemos,NrFields + 1)
  END
  IF Result = 0
    Result = SELF.ParseKeyDefinitions(Def,TotalLen,Pos,NrIndexes)
  END
  DISPOSE(Def)
  IF Result <> 0
    SELF.FreeFields()
    SELF.FreeKeys()
    RETURN Result
  END
  IF RECORDS(SELF.FieldQ) = 0
    SELF.FreeKeys()
    RETURN SELF.SetLastError(TpsErrFieldDefMissing,'No fields found in table definition; table=' & SELF.CurrentTable)
  END
  SELF.ParsedLayoutTable = SELF.CurrentTable
  RETURN 0

TpsParserType.ParseFieldDefinitions PROCEDURE(*STRING pDefinition,LONG pTotalLen,*LONG pPosition,LONG pFieldCount)
I                                 LONG
Pos                               LONG
FieldType                         LONG
FieldName                         &STRING
NameLen                           LONG
ShortLen                          LONG
Elements                          LONG
FieldLen                          LONG
FieldFlags                        LONG
IndexNo                           LONG
StringLen                         LONG
Result                            LONG
  CODE
  Pos = pPosition
  FieldName &= NULL
  LOOP I = 1 TO pFieldCount
    IF Pos + 3 > pTotalLen
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrFieldDefHeader,'Incomplete field definition header; table=' & SELF.CurrentTable & ' field=' & I & ' offset=' & Pos & ' total=' & pTotalLen)
    END
    FieldType = SELF.ReadByte(pDefinition,Pos); Pos += 1
    FieldName &= NULL
    CLEAR(SELF.FieldQ)
    SELF.FieldQ.TableNo = SELF.CurrentTable
    SELF.FieldQ.FieldNo = I
    SELF.FieldQ.FieldType = FieldType
    SELF.FieldQ.Offset = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    NameLen = SELF.ReadZeroString(pDefinition,pTotalLen,Pos)
    IF NameLen < 0
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
    IF Pos + 8 > pTotalLen
      Result = SELF.SetLastError(TpsErrFieldDefBody,'Incomplete field definition body; table=' & SELF.CurrentTable & ' field=' & I & ' name=' & CLIP(FieldName) & ' offset=' & Pos & ' total=' & pTotalLen)
      DISPOSE(FieldName)
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
    Elements = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    FieldLen = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    FieldFlags = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    IndexNo = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    IF Elements < 1 OR FieldLen < 1 OR FieldLen % Elements <> 0
      IF ~SELF.FieldQ.Name &= NULL
        DISPOSE(SELF.FieldQ.Name)
      END
      IF ~SELF.FieldQ.ShortName &= NULL
        DISPOSE(SELF.FieldQ.ShortName)
      END
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrFieldDataInvalid,'Invalid field dimensions; table=' & SELF.CurrentTable & ' field=' & I & ' elements=' & Elements & ' length=' & FieldLen)
    END
    SELF.FieldQ.Elements = Elements
    SELF.FieldQ.Length = FieldLen
    SELF.FieldQ.Flags = FieldFlags
    SELF.FieldQ.IndexNo = IndexNo
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
        IF Pos + 2 > pTotalLen
          Result = SELF.SetLastError(TpsErrBcdMetadata,'Incomplete BCD metadata; table=' & SELF.CurrentTable & ' field=' & I & ' name=' & CLIP(FieldName) & ' offset=' & Pos & ' total=' & pTotalLen)
          IF ~SELF.FieldQ.Name &= NULL
            DISPOSE(SELF.FieldQ.Name)
          END
          IF ~SELF.FieldQ.ShortName &= NULL
            DISPOSE(SELF.FieldQ.ShortName)
          END
          SELF.FreeFields()
          RETURN TpsErrBcdMetadata
        END
        SELF.FieldQ.BcdDigitsAfterDecimal = SELF.ReadByte(pDefinition,Pos); Pos += 1
        SELF.FieldQ.BcdLengthOfElement = SELF.ReadByte(pDefinition,Pos); Pos += 1
    END
    CASE FieldType
      OF TpsFieldString OROF TpsFieldCString OROF TpsFieldPString
        IF Pos + 2 > pTotalLen
          Result = SELF.SetLastError(TpsErrStringMetadata,'Incomplete string metadata; table=' & SELF.CurrentTable & ' field=' & I & ' name=' & CLIP(FieldName) & ' offset=' & Pos & ' total=' & pTotalLen)
          DISPOSE(SELF.FieldQ.Name)
          DISPOSE(SELF.FieldQ.ShortName)
          SELF.FreeFields()
          RETURN TpsErrStringMetadata
        END
        StringLen = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
        SELF.FieldQ.StringLength = StringLen
        NameLen = SELF.ReadZeroString(pDefinition,pTotalLen,Pos)
        IF NameLen < 0
          DISPOSE(SELF.FieldQ.Name)
          DISPOSE(SELF.FieldQ.ShortName)
          SELF.FreeFields()
          RETURN SELF.SetLastError(TpsErrStringExternalName,'Unterminated string external name; table=' & SELF.CurrentTable & ' field=' & I)
        END
        IF NameLen > 0
          SELF.FieldQ.StringMask &= NEW(STRING(NameLen))
          SELF.FieldQ.StringMask = SELF.ReturnBuffer
        END
        IF NameLen = 0
          IF Pos + 1 > pTotalLen
            DISPOSE(SELF.FieldQ.Name)
            DISPOSE(SELF.FieldQ.ShortName)
            IF ~SELF.FieldQ.StringMask &= NULL
              DISPOSE(SELF.FieldQ.StringMask)
            END
            SELF.FreeFields()
            RETURN SELF.SetLastError(TpsErrStringExternalName,'Incomplete string external-name marker; table=' & SELF.CurrentTable & ' field=' & I & ' offset=' & Pos & ' total=' & pTotalLen)
          END
          Pos += 1
        END
    END
    ADD(SELF.FieldQ)
    IF ERRORCODE()
      IF ~SELF.FieldQ.Name &= NULL
        DISPOSE(SELF.FieldQ.Name)
      END
      IF ~SELF.FieldQ.ShortName &= NULL
        DISPOSE(SELF.FieldQ.ShortName)
      END
      IF ~SELF.FieldQ.StringMask &= NULL
        DISPOSE(SELF.FieldQ.StringMask)
      END
      SELF.FreeFields()
      RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS field definition')
    END
  END
  pPosition = Pos
  RETURN 0

TpsParserType.ParseMemoDefinitions PROCEDURE(*STRING pDefinition,LONG pTotalLen,*LONG pPosition,LONG pMemoCount,LONG pFirstFieldNo)
I                                 LONG
Pos                               LONG
MemoName                          &STRING
ExternalName                      &STRING
NameLen                           LONG
ShortLen                          LONG
MemoLen                           LONG
MemoFlags                         LONG
Result                            LONG
  CODE
  Pos = pPosition
  MemoName &= NULL
  ExternalName &= NULL
  LOOP I = 0 TO pMemoCount - 1
    NameLen = SELF.ReadZeroString(pDefinition,pTotalLen,Pos)
    IF NameLen < 0
      SELF.FreeFields()
      RETURN SELF.SetLastError(TpsErrMemoExternalName,'Unterminated MEMO external name; table=' & SELF.CurrentTable & ' memo=' & I)
    END
    ExternalName &= NULL
    IF NameLen > 0
      ExternalName &= NEW(STRING(NameLen))
      ExternalName = SELF.ReturnBuffer
    END
    IF NameLen = 0
      IF Pos + 1 > pTotalLen
        SELF.FreeFields()
        RETURN SELF.SetLastError(TpsErrMemoExternalName,'Incomplete memo external-name marker; table=' & SELF.CurrentTable & ' memo=' & I & ' offset=' & Pos & ' total=' & pTotalLen)
      END
      Pos += 1
    END
    NameLen = SELF.ReadZeroString(pDefinition,pTotalLen,Pos)
    IF NameLen < 0
      IF ~ExternalName &= NULL
        DISPOSE(ExternalName)
      END
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
    IF Pos + 4 > pTotalLen
      Result = SELF.SetLastError(TpsErrMemoDef,'Incomplete memo definition; table=' & SELF.CurrentTable & ' memo=' & I & ' name=' & CLIP(MemoName) & ' offset=' & Pos & ' total=' & pTotalLen)
      DISPOSE(MemoName)
      IF ~ExternalName &= NULL
        DISPOSE(ExternalName)
      END
      SELF.FreeFields()
      RETURN TpsErrMemoDef
    END
    MemoLen = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    MemoFlags = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    CLEAR(SELF.FieldQ)
    SELF.FieldQ.TableNo = SELF.CurrentTable
    SELF.FieldQ.FieldNo = pFirstFieldNo + I
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
    SELF.FieldQ.MemoLength = MemoLen
    SELF.FieldQ.MemoFlags = MemoFlags
    SELF.FieldQ.ExternalName &= ExternalName
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
      IF ~SELF.FieldQ.ExternalName &= NULL
        DISPOSE(SELF.FieldQ.ExternalName)
      END
      SELF.FreeFields()
      RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS MEMO definition')
    END
  END
  pPosition = Pos
  RETURN 0

TpsParserType.ParseKeyDefinitions PROCEDURE(*STRING pDefinition,LONG pTotalLen,*LONG pPosition,LONG pKeyCount)
I                                 LONG
J                                 LONG
Pos                               LONG
KeyName                           &STRING
ExternalName                      &STRING
NameLen                           LONG
KeyFlags                          LONG
KeyFieldCount                     LONG
KeyFieldIndex                     LONG
KeyFieldFlags                     LONG
  CODE
  Pos = pPosition
  KeyName &= NULL
  ExternalName &= NULL
  LOOP I = 1 TO pKeyCount
    NameLen = SELF.ReadZeroString(pDefinition,pTotalLen,Pos)
    IF NameLen < 0
      SELF.FreeFields()
      SELF.FreeKeys()
      RETURN SELF.SetLastError(TpsErrIndexDef,'Unterminated index external name; table=' & SELF.CurrentTable & ' key=' & I)
    END
    ExternalName &= NULL
    IF NameLen > 0
      ExternalName &= NEW(STRING(NameLen))
      ExternalName = SELF.ReturnBuffer
    ELSE
      IF Pos + 1 > pTotalLen OR SELF.ReadByte(pDefinition,Pos) <> 1
        SELF.FreeFields()
        SELF.FreeKeys()
        RETURN SELF.SetLastError(TpsErrIndexDef,'Invalid index external-name marker; table=' & SELF.CurrentTable & ' key=' & I)
      END
      Pos += 1
    END
    NameLen = SELF.ReadZeroString(pDefinition,pTotalLen,Pos)
    IF NameLen < 0
      IF ~ExternalName &= NULL
        DISPOSE(ExternalName)
      END
      SELF.FreeFields()
      SELF.FreeKeys()
      RETURN SELF.SetLastError(TpsErrIndexDef,'Unterminated index name; table=' & SELF.CurrentTable & ' key=' & I)
    END
    KeyName &= NEW(STRING(CHOOSE(NameLen > 0,NameLen,1)))
    IF NameLen > 0
      KeyName = SELF.ReturnBuffer
    ELSE
      CLEAR(KeyName)
    END
    IF Pos + 3 > pTotalLen
      DISPOSE(KeyName)
      IF ~ExternalName &= NULL
        DISPOSE(ExternalName)
      END
      SELF.FreeFields()
      SELF.FreeKeys()
      RETURN SELF.SetLastError(TpsErrIndexDef,'Incomplete index definition; table=' & SELF.CurrentTable & ' key=' & I)
    END
    KeyFlags = SELF.ReadByte(pDefinition,Pos); Pos += 1
    KeyFieldCount = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
    CLEAR(SELF.KeyQ)
    SELF.KeyQ.TableNo = SELF.CurrentTable
    SELF.KeyQ.KeyNo = I
    SELF.KeyQ.Name &= KeyName
    SELF.KeyQ.ExternalName &= ExternalName
    SELF.KeyQ.Flags = KeyFlags
    SELF.KeyQ.FieldCount = KeyFieldCount
    ADD(SELF.KeyQ)
    IF ERRORCODE()
      DISPOSE(KeyName)
      IF ~ExternalName &= NULL
        DISPOSE(ExternalName)
      END
      SELF.FreeFields()
      SELF.FreeKeys()
      RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS index definition')
    END
    LOOP J = 1 TO KeyFieldCount
      IF Pos + 4 > pTotalLen
        SELF.FreeFields()
        SELF.FreeKeys()
        RETURN SELF.SetLastError(TpsErrIndexDef,'Incomplete index component; table=' & SELF.CurrentTable & ' key=' & I & ' rank=' & J)
      END
      KeyFieldIndex = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
      KeyFieldFlags = SELF.ReadLeShort(pDefinition,Pos); Pos += 2
      CLEAR(SELF.KeyFieldQ)
      SELF.KeyFieldQ.TableNo = SELF.CurrentTable
      SELF.KeyFieldQ.KeyNo = I
      SELF.KeyFieldQ.Rank = J
      SELF.KeyFieldQ.FieldIndex = KeyFieldIndex
      SELF.KeyFieldQ.Flags = KeyFieldFlags
      SELF.KeyFieldQ.Ascending = CHOOSE(BAND(KeyFieldFlags,TpsKeyFieldDescendingFlag) = 0,TRUE,FALSE)
      ADD(SELF.KeyFieldQ)
      IF ERRORCODE()
        SELF.FreeFields()
        SELF.FreeKeys()
        RETURN SELF.SetLastError(ERRORCODE(),'Could not store TPS index component')
      END
    END
  END
  pPosition = Pos
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
  IF SELF.ParsedLayoutTable <> pTableNo
    Result = SELF.ParseTableLayout()
    IF Result <> 0
      RETURN Result
    END
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

TpsParserType.EnsureDataRange PROCEDURE
I                               LONG
  CODE
  IF SELF.DataRangeTable = SELF.CurrentTable
    RETURN
  END
  SELF.DataRangeTable = SELF.CurrentTable
  SELF.DataRangeFirst = 0
  SELF.DataRangeCount = 0
  LOOP I = 1 TO RECORDS(SELF.DataQ)
    GET(SELF.DataQ,I)
    IF SELF.DataQ.TableNo = SELF.CurrentTable
      IF SELF.DataRangeFirst = 0
        SELF.DataRangeFirst = I
      END
      SELF.DataRangeCount += 1
    ELSIF SELF.DataRangeFirst > 0
      BREAK
    END
  END
  IF SELF.CurrentRecord < SELF.DataRangeFirst OR |
      SELF.CurrentRecord >= SELF.DataRangeFirst + SELF.DataRangeCount
    SELF.InvalidateMemoChainCache()
    SELF.CurrentRecord = 0
  END

TpsParserType.InvalidateDataRange PROCEDURE
  CODE
  SELF.DataRangeTable = -1
  SELF.DataRangeFirst = 0
  SELF.DataRangeCount = 0

TpsParserType.EnsureMemoQSorted PROCEDURE
  CODE
  IF ~SELF.MemoQDirty
    RETURN
  END
  SELF.InvalidateMemoChainCache()
  SORT(SELF.MemoQ,+SELF.MemoQ.TableNo,+SELF.MemoQ.Owner,+SELF.MemoQ.MemoIndex,+SELF.MemoQ.Sequence,+SELF.MemoQ.Arrival)
  SELF.MemoQDirty = FALSE

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
  SELF.EnsureMemoQSorted()
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

TpsParserType.FindMemoChainCache PROCEDURE(LONG pOwner,LONG pMemoIndex)
I                                  LONG
  CODE
  LOOP I = 1 TO RECORDS(SELF.MemoChainQ)
    GET(SELF.MemoChainQ,I)
    IF SELF.MemoChainQ.TableNo = SELF.CurrentTable AND |
        SELF.MemoChainQ.Owner = pOwner AND |
        SELF.MemoChainQ.MemoIndex = pMemoIndex
      RETURN I
    END
  END
  RETURN 0

TpsParserType.ResolveMemoChain PROCEDURE(LONG pOwner,LONG pMemoIndex,*LONG pRawLen,*LONG pCacheIndex)
I                                LONG
J                                LONG
Last                             LONG
Expected                         LONG
PartFirst                        LONG
PartCount                        LONG
CacheError                       LONG
Found                            BYTE
State                            BYTE
  CODE
  pRawLen = 0
  pCacheIndex = 0
  SELF.EnsureMemoQSorted()
  pCacheIndex = SELF.FindMemoChainCache(pOwner,pMemoIndex)
  IF pCacheIndex > 0
    GET(SELF.MemoChainQ,pCacheIndex)
    pRawLen = SELF.MemoChainQ.RawLen
    RETURN SELF.MemoChainQ.State
  END
  PartFirst = RECORDS(SELF.MemoPartQ) + 1
  State = TpsMemoStateEmpty
  I = SELF.FindFirstMemoChunk(pOwner,pMemoIndex)
  IF I > 0
    State = TpsMemoStateComplete
    LOOP WHILE I <= RECORDS(SELF.MemoQ)
      GET(SELF.MemoQ,I)
      IF SELF.MemoQ.TableNo <> SELF.CurrentTable OR |
          SELF.MemoQ.Owner <> pOwner OR |
          SELF.MemoQ.MemoIndex <> pMemoIndex
        BREAK
      END
      IF SELF.MemoQ.Sequence <> Expected
        State = TpsMemoStateDamaged
        BREAK
      END
      Found = TRUE
      Last = I
      J = I + 1
      LOOP WHILE J <= RECORDS(SELF.MemoQ)
        GET(SELF.MemoQ,J)
        IF SELF.MemoQ.TableNo <> SELF.CurrentTable OR |
            SELF.MemoQ.Owner <> pOwner OR |
            SELF.MemoQ.MemoIndex <> pMemoIndex OR |
            SELF.MemoQ.Sequence <> Expected
          BREAK
        END
        Last = J
        J += 1
      END
      GET(SELF.MemoQ,Last)
      IF SELF.MemoQ.DataLen < 0 OR SELF.MemoQ.DataLen > 7FFFFFFFH - pRawLen
        State = TpsMemoStateDamaged
        BREAK
      END
      IF SELF.MemoQ.DataLen > 0
        IF SELF.MemoQ.Payload &= NULL
          State = TpsMemoStateDamaged
          BREAK
        END
        IF SELF.MemoQ.DataLen > SIZE(SELF.MemoQ.Payload)
          State = TpsMemoStateDamaged
          BREAK
        END
      END
      CLEAR(SELF.MemoPartQ)
      SELF.MemoPartQ.MemoQIndex = Last
      ADD(SELF.MemoPartQ)
      IF ERRORCODE()
        CacheError = ERRORCODE()
        State = TpsMemoStateDamaged
        BREAK
      END
      pRawLen += SELF.MemoQ.DataLen
      Expected += 1
      I = J
    END
  END
  IF ~Found AND State = TpsMemoStateComplete
    State = TpsMemoStateEmpty
  END
  PartCount = RECORDS(SELF.MemoPartQ) - PartFirst + 1
  IF State <> TpsMemoStateComplete
    LOOP WHILE RECORDS(SELF.MemoPartQ) >= PartFirst
      GET(SELF.MemoPartQ,RECORDS(SELF.MemoPartQ))
      DELETE(SELF.MemoPartQ)
    END
    PartCount = 0
    pRawLen = 0
  END
  IF CacheError <> 0
    SELF.InvalidateMemoChainCache()
    CacheError = SELF.SetLastError(CacheError,'Could not cache a validated TPS MEMO fragment.')
    RETURN TpsMemoStateDamaged
  END
  CLEAR(SELF.MemoChainQ)
  SELF.MemoChainQ.TableNo = SELF.CurrentTable
  SELF.MemoChainQ.Owner = pOwner
  SELF.MemoChainQ.MemoIndex = pMemoIndex
  SELF.MemoChainQ.State = State
  SELF.MemoChainQ.RawLen = pRawLen
  SELF.MemoChainQ.PartFirst = PartFirst
  SELF.MemoChainQ.PartCount = PartCount
  ADD(SELF.MemoChainQ)
  IF ERRORCODE()
    CacheError = ERRORCODE()
    SELF.InvalidateMemoChainCache()
    pRawLen = 0
    CacheError = SELF.SetLastError(CacheError,'Could not cache a validated TPS MEMO chain.')
    RETURN TpsMemoStateDamaged
  END
  pCacheIndex = RECORDS(SELF.MemoChainQ)
  RETURN State

TpsParserType.CopyResolvedMemo PROCEDURE(LONG pCacheIndex,*STRING pRaw,LONG pMaxLen)
I                                LONG
PartIndex                        LONG
RawLen                           LONG
CopyLen                          LONG
  CODE
  IF pCacheIndex < 1 OR pCacheIndex > RECORDS(SELF.MemoChainQ) OR pMaxLen < 1
    RETURN 0
  END
  IF pMaxLen > SIZE(pRaw)
    pMaxLen = SIZE(pRaw)
  END
  GET(SELF.MemoChainQ,pCacheIndex)
  IF SELF.MemoChainQ.State <> TpsMemoStateComplete
    RETURN 0
  END
  LOOP I = 0 TO SELF.MemoChainQ.PartCount - 1
    IF RawLen >= pMaxLen
      BREAK
    END
    PartIndex = SELF.MemoChainQ.PartFirst + I
    IF PartIndex < 1 OR PartIndex > RECORDS(SELF.MemoPartQ)
      RETURN 0
    END
    GET(SELF.MemoPartQ,PartIndex)
    IF SELF.MemoPartQ.MemoQIndex < 1 OR SELF.MemoPartQ.MemoQIndex > RECORDS(SELF.MemoQ)
      RETURN 0
    END
    GET(SELF.MemoQ,SELF.MemoPartQ.MemoQIndex)
    IF SELF.MemoQ.DataLen < 0
      RETURN 0
    END
    IF SELF.MemoQ.DataLen > 0
      IF SELF.MemoQ.Payload &= NULL
        RETURN 0
      END
      IF SELF.MemoQ.DataLen > SIZE(SELF.MemoQ.Payload)
        RETURN 0
      END
    END
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
  END
  RETURN RawLen

TpsParserType.InvalidateMemoChainCache PROCEDURE
  CODE
  IF ~SELF.MemoChainQ &= NULL
    FREE(SELF.MemoChainQ)
  END
  IF ~SELF.MemoPartQ &= NULL
    FREE(SELF.MemoPartQ)
  END

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
