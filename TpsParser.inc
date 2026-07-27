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

!Type declarations

  INCLUDE('TpsFormat.inc'),ONCE

TpsTypeNameMax      EQUATE(32)
TpsMemoStateEmpty   EQUATE(0)
TpsMemoStateComplete EQUATE(1)
TpsMemoStateDamaged EQUATE(2)
TpsKeyFlagDup       EQUATE(1)
TpsKeyFlagOpt       EQUATE(2)
TpsKeyFlagNoCase    EQUATE(4)
TpsKeyFlagPrimary   EQUATE(10H)

TpsDataQueue        QUEUE,TYPE
TableNo               LONG
RecordNumber          LONG
PayloadLen            LONG
Payload               &STRING
SourceOffset          LONG
Arrival               LONG
                    END

TpsMemoQueue        QUEUE,TYPE
TableNo               LONG
Owner                 LONG
MemoIndex             LONG
Sequence              LONG
DataLen               LONG
Payload               &STRING
Arrival               LONG
                    END

TpsMemoChainQueue   QUEUE,TYPE
TableNo               LONG
Owner                 LONG
MemoIndex             LONG
State                 BYTE
RawLen                LONG
PartFirst             LONG
PartCount             LONG
                    END

TpsMemoPartQueue    QUEUE,TYPE
MemoQIndex            LONG
                    END

TpsBlockRangeQueue  QUEUE,TYPE
BlockNo               LONG
StartOfs              LONG
EndOfs                LONG
                    END

TpsTableDefQueue    QUEUE,TYPE
TableNo               LONG
BlockNo               LONG
DataLen               LONG
Payload               &STRING
Arrival               LONG
                    END

TpsTableNameQueue   QUEUE,TYPE
TableNo               LONG
Name                  &STRING
Arrival               LONG
                    END

TpsFieldQueue       QUEUE,TYPE
TableNo               LONG
FieldNo               LONG
Name                  &STRING
ShortName             &STRING
FieldType             LONG
TypeName              STRING(TpsTypeNameMax)
Offset                LONG
Length                LONG
Elements              LONG
Flags                 LONG
IndexNo               LONG
StringLength          LONG
StringMask            &STRING
BcdDigitsAfterDecimal LONG
BcdLengthOfElement    LONG
IsMemo                BYTE
IsBlob                BYTE
MemoIndex             LONG
MemoLength            LONG
MemoFlags             LONG
ExternalName          &STRING
                    END

TpsKeyQueue         QUEUE,TYPE
TableNo               LONG
KeyNo                 LONG
Name                  &STRING
ExternalName          &STRING
Flags                 LONG
FieldCount            LONG
                    END

TpsKeyFieldQueue    QUEUE,TYPE
TableNo               LONG
KeyNo                 LONG
Rank                  LONG
FieldIndex            LONG
Flags                 LONG
Ascending             BYTE
                    END

TpsProgressSinkType CLASS,TYPE,MODULE('TpsParser'),LINK('TpsParser')
Update                PROCEDURE(STRING pStage,LONG pCompleted,LONG pTotal),VIRTUAL
                    END

TpsParserType       CLASS,TYPE,MODULE('TpsParser'),LINK('TpsParser'),TYPE

! Initialization and cleanup
Init                  PROCEDURE(STRING pFileName),LONG
Init                  PROCEDURE(STRING pFileName,STRING pOwner),LONG
Init                  PROCEDURE(STRING pFileName,STRING pOwner,BYTE pIgnoreErrors),LONG
InitMetadata          PROCEDURE(STRING pFileName),LONG
InitMetadata          PROCEDURE(STRING pFileName,STRING pOwner),LONG
InitRecovering        PROCEDURE(STRING pFileName),LONG
InitRecovering        PROCEDURE(STRING pFileName,STRING pOwner),LONG
Kill                  PROCEDURE
SetProgressSink       PROCEDURE(*TpsProgressSinkType pSink)
ClearProgressSink     PROCEDURE

! Error information
GetErrorCode          PROCEDURE,LONG
GetError              PROCEDURE,STRING

! Table selection and metadata
Tables                PROCEDURE,LONG
GetTableName          PROCEDURE(LONG pTableIndex),STRING
SetTable              PROCEDURE(LONG pTableIndex = 0),LONG,PROC
GetCurrentTableNumber PROCEDURE,LONG
GetRecordLength       PROCEDURE,LONG

! Record navigation
Records               PROCEDURE,LONG
Get                   PROCEDURE(LONG pRecordNo),LONG,PROC
Set                   PROCEDURE(LONG pRecordNo = 0),LONG,PROC
Next                  PROCEDURE,BYTE
GetCurrentRecordNumber PROCEDURE,LONG
GetCurrentRecordOffset PROCEDURE,LONG
GetRecoveryIssueCount PROCEDURE,LONG
GetSourceEncrypted    PROCEDURE,BYTE

! Field metadata
Fields                PROCEDURE,LONG
GetFieldNameByNumber  PROCEDURE(LONG pFieldNo),STRING
GetFieldType          PROCEDURE(STRING pFieldName),STRING
GetFieldTypeByNumber  PROCEDURE(LONG pFieldNo),STRING
GetFieldTypeCodeByNumber PROCEDURE(LONG pFieldNo),LONG
GetFieldDimension     PROCEDURE(STRING pFieldName),LONG
GetFieldDimensionByNumber PROCEDURE(LONG pFieldNo),LONG
GetFieldSize          PROCEDURE(STRING pFieldName),LONG
GetFieldSizeByNumber  PROCEDURE(LONG pFieldNo),LONG
GetFieldDecimals      PROCEDURE(STRING pFieldName),LONG
GetFieldDecimalsByNumber  PROCEDURE(LONG pFieldNo),LONG
GetFieldNumber        PROCEDURE(STRING pFieldName),LONG
GetFieldOffsetByNumber PROCEDURE(LONG pFieldNo),LONG
GetFieldLengthByNumber PROCEDURE(LONG pFieldNo),LONG
GetFieldFlagsByNumber PROCEDURE(LONG pFieldNo),LONG
GetFieldIndexByNumber PROCEDURE(LONG pFieldNo),LONG
GetFieldStringMaskByNumber PROCEDURE(LONG pFieldNo),STRING
GetFieldIsMemoByNumber PROCEDURE(LONG pFieldNo),BYTE
GetFieldIsBlobByNumber PROCEDURE(LONG pFieldNo),BYTE
GetMemoLengthByNumber PROCEDURE(LONG pFieldNo),LONG
GetMemoFlagsByNumber PROCEDURE(LONG pFieldNo),LONG
GetExternalNameByNumber PROCEDURE(LONG pFieldNo),STRING

! Key and index metadata
Keys                  PROCEDURE,LONG
GetKeyName            PROCEDURE(LONG pKeyNo),STRING
GetKeyFlags           PROCEDURE(LONG pKeyNo),LONG
GetKeyExternalName    PROCEDURE(LONG pKeyNo),STRING
GetKeyFieldCount      PROCEDURE(LONG pKeyNo),LONG
GetKeyFieldIndex      PROCEDURE(LONG pKeyNo,LONG pRank),LONG
GetKeyFieldAscending  PROCEDURE(LONG pKeyNo,LONG pRank),BYTE

! Generic field value
GetField              PROCEDURE(STRING pFieldName,LONG pDimension = 0),STRING
GetFieldByNumber      PROCEDURE(LONG pFieldNo,LONG pDimension = 0),STRING

! Typed scalar field values
GetStringField        PROCEDURE(STRING pFieldName,LONG pDimension = 0),STRING
GetStringFieldByNumber    PROCEDURE(LONG pFieldNo,LONG pDimension = 0),STRING
GetByteField          PROCEDURE(STRING pFieldName,LONG pDimension = 0),BYTE
GetByteFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension = 0),BYTE
GetShortField         PROCEDURE(STRING pFieldName,LONG pDimension = 0),SHORT
GetShortFieldByNumber PROCEDURE(LONG pFieldNo,LONG pDimension = 0),SHORT
GetUShortField        PROCEDURE(STRING pFieldName,LONG pDimension = 0),USHORT
GetUShortFieldByNumber    PROCEDURE(LONG pFieldNo,LONG pDimension = 0),USHORT
GetLongField          PROCEDURE(STRING pFieldName,LONG pDimension = 0),LONG
GetLongFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension = 0),LONG
GetULongField         PROCEDURE(STRING pFieldName,LONG pDimension = 0),ULONG
GetULongFieldByNumber PROCEDURE(LONG pFieldNo,LONG pDimension = 0),ULONG
GetRealField          PROCEDURE(STRING pFieldName,LONG pDimension = 0),REAL
GetRealFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension = 0),REAL
GetDecimalField       PROCEDURE(STRING pFieldName,LONG pDimension = 0),STRING
GetDecimalFieldByNumber   PROCEDURE(LONG pFieldNo,LONG pDimension = 0),STRING
GetRawField           PROCEDURE(STRING pFieldName,LONG pDimension = 0),STRING
GetRawFieldByNumber   PROCEDURE(LONG pFieldNo,LONG pDimension = 0),STRING
GetDateField          PROCEDURE(STRING pFieldName,LONG pDimension = 0),LONG
GetDateFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension = 0),LONG
GetTimeField          PROCEDURE(STRING pFieldName,LONG pDimension = 0),LONG
GetTimeFieldByNumber  PROCEDURE(LONG pFieldNo,LONG pDimension = 0),LONG

! MEMO and BLOB field values
GetMemoField          PROCEDURE(STRING pFieldName),STRING
GetMemoFieldByNumber  PROCEDURE(LONG pFieldNo),STRING
GetBlobField          PROCEDURE(STRING pFieldName,*BLOB pBlob),LONG,PROC
GetBlobFieldByNumber  PROCEDURE(LONG pFieldNo,*BLOB pBlob),LONG,PROC
GetMemoStateByNumber  PROCEDURE(LONG pFieldNo),BYTE
GetBlobValueByNumber PROCEDURE(LONG pFieldNo,*LONG pBlobLength),STRING

! Protected diagnostic state
Src                   &STRING,PROTECTED
SrcLen                LONG,PROTECTED
GetBlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength),STRING,PROTECTED
AllowMissingDefinition PROCEDURE,BYTE,PROTECTED,VIRTUAL

! Internal members
WorkPage              &STRING,PRIVATE
WorkPageLen           LONG,PRIVATE
CurrentRecord         LONG,PRIVATE
CurrentTable          LONG,PROTECTED
SourceFileName        STRING(260),PRIVATE
LastError             LONG,PRIVATE
LastErrorText         &STRING,PRIVATE
ReturnBuffer          &STRING,PRIVATE
BlobPreviewBuffer     &STRING,PRIVATE
IgnoreErrors          BYTE,PRIVATE
ParsePass             BYTE,PRIVATE
Arrival               LONG,PRIVATE
CurrentPageOffset     LONG,PRIVATE
CurrentRecordLength   LONG,PRIVATE
RecoveryIssues        LONG,PRIVATE
SourceEncrypted       BYTE,PRIVATE
ProgressSink          &TpsProgressSinkType,PRIVATE
DataRangeTable        LONG,PRIVATE
DataRangeFirst        LONG,PRIVATE
DataRangeCount        LONG,PRIVATE
MemoQDirty            BYTE,PRIVATE
BlockRangesReady      BYTE,PRIVATE
ParsedLayoutTable     LONG,PRIVATE
DataQ                 &TpsDataQueue,PROTECTED
MemoQ                 &TpsMemoQueue,PROTECTED
MemoChainQ            &TpsMemoChainQueue,PRIVATE
MemoPartQ             &TpsMemoPartQueue,PRIVATE
BlockRangeQ           &TpsBlockRangeQueue,PRIVATE
TableDefQ             &TpsTableDefQueue,PROTECTED
TableNameQ            &TpsTableNameQueue,PROTECTED
FieldQ                &TpsFieldQueue,PROTECTED
KeyQ                  &TpsKeyQueue,PROTECTED
KeyFieldQ             &TpsKeyFieldQueue,PROTECTED
Construct             PROCEDURE,PRIVATE
Destruct              PROCEDURE,PRIVATE
InitCore              PROCEDURE(STRING pFileName,STRING pOwner,BYTE pHasOwner,BYTE pIgnoreErrors,BYTE pMetadataOnly),LONG,PRIVATE
ValidateHeader        PROCEDURE,LONG,PRIVATE
ResolveTableNumber    PROCEDURE(LONG pTableIndex),LONG,PRIVATE
GetTableNameByTableNumber PROCEDURE(LONG pTableNo),STRING,PRIVATE
GetSourceTableName    PROCEDURE,STRING,PRIVATE
LoadSource            PROCEDURE(STRING pFileName),LONG,PRIVATE
DecryptSource         PROCEDURE(STRING pOwner),LONG,PRIVATE
BuildOwnerKey         PROCEDURE(STRING pOwner,*STRING pKey),PRIVATE
ShuffleKey            PROCEDURE(*STRING pKey),PRIVATE
DecryptRange          PROCEDURE(LONG pOffset,LONG pLength,*STRING pKey),LONG,PRIVATE
DecryptBlock64        PROCEDURE(LONG pOffset,*STRING pKey),PRIVATE
ParseTps              PROCEDURE(BYTE pMetadataOnly),LONG,PRIVATE
BuildBlockRangeCache  PROCEDURE,LONG,PRIVATE
ParseAllBlocks        PROCEDURE,LONG,PRIVATE
ParseBlock            PROCEDURE(LONG pStart,LONG pEnd),LONG,PRIVATE
IsCompletePage        PROCEDURE(LONG pPos,LONG pPageSize,LONG pEnd),BYTE,PRIVATE
ParsePage             PROCEDURE(LONG pPos,LONG pEnd),LONG,PRIVATE
BuildWorkPage         PROCEDURE(LONG pCompressedStart,LONG pCompressedLen,LONG pPageSize,LONG pPageSizeUncompressed,LONG pFlags),LONG,PRIVATE
DecodeRleCount        PROCEDURE(LONG pCompressedStart,LONG pCompressedLen,*LONG pCompressedPos,*LONG pCount),LONG,PRIVATE
ParseRecords          PROCEDURE(*STRING pData,LONG pLen,LONG pRecordCount),LONG,PRIVATE
ProcessRecord         PROCEDURE(*STRING pRecord,LONG pRecordLen,LONG pHeaderLen),LONG,PRIVATE
ParseTableLayout      PROCEDURE,LONG,PRIVATE
ParseFieldDefinitions PROCEDURE(*STRING pDefinition,LONG pTotalLen,*LONG pPosition,LONG pFieldCount),LONG,PRIVATE
ParseMemoDefinitions PROCEDURE(*STRING pDefinition,LONG pTotalLen,*LONG pPosition,LONG pMemoCount,LONG pFirstFieldNo),LONG,PRIVATE
ParseKeyDefinitions  PROCEDURE(*STRING pDefinition,LONG pTotalLen,*LONG pPosition,LONG pKeyCount),LONG,PRIVATE
TableDefinitionIsComplete PROCEDURE(LONG pTableNo,*LONG pTotalLen),BYTE,PRIVATE
ValidateRecordPayload PROCEDURE(LONG pTableNo,*STRING pData,LONG pLen),LONG,PRIVATE
ReadZeroString        PROCEDURE(*STRING pData,LONG pLen,*LONG pPos),LONG,PRIVATE
StripTablePrefix      PROCEDURE(STRING pName),STRING,PRIVATE
ResolveFieldValue     PROCEDURE(LONG pFieldNo,LONG pDimension,*LONG pOffset,*LONG pLength),BYTE,PRIVATE
EnsureDataRange       PROCEDURE,PRIVATE
InvalidateDataRange   PROCEDURE,PRIVATE
EnsureMemoQSorted     PROCEDURE,PRIVATE
CompareMemoKey        PROCEDURE(LONG pIndex,LONG pOwner,LONG pMemoIndex),LONG,PRIVATE
FindFirstMemoChunk    PROCEDURE(LONG pOwner,LONG pMemoIndex),LONG,PRIVATE
FindMemoChainCache    PROCEDURE(LONG pOwner,LONG pMemoIndex),LONG,PRIVATE
ResolveMemoChain      PROCEDURE(LONG pOwner,LONG pMemoIndex,*LONG pRawLen,*LONG pCacheIndex),BYTE,PRIVATE
CopyResolvedMemo      PROCEDURE(LONG pCacheIndex,*STRING pRaw,LONG pMaxLen),LONG,PRIVATE
InvalidateMemoChainCache PROCEDURE,PRIVATE
FindCurrentKeyRecord  PROCEDURE(LONG pKeyNo),LONG,PRIVATE
FindCurrentKeyFieldRecord PROCEDURE(LONG pKeyNo,LONG pRank),LONG,PRIVATE
LoadBlobPreviewByNumber PROCEDURE(LONG pFieldNo,LONG pMaxBytes,*LONG pBlobLength),LONG,PRIVATE
RollbackData          PROCEDURE(LONG pKeep),PRIVATE
RollbackMemos         PROCEDURE(LONG pKeep),PRIVATE
RollbackTableDefs     PROCEDURE(LONG pKeep),PRIVATE
RollbackTableNames    PROCEDURE(LONG pKeep),PRIVATE
FreeData              PROCEDURE,PRIVATE
FreeMemos             PROCEDURE,PRIVATE
FreeTableDefs         PROCEDURE,PRIVATE
FreeTableNames        PROCEDURE,PRIVATE
FreeFields            PROCEDURE,PROTECTED
FreeKeys              PROCEDURE,PRIVATE
SetReturnBuffer       PROCEDURE(*STRING pData,LONG pPos,LONG pLen),STRING,PRIVATE
TrimFixedString       PROCEDURE(*STRING pData,LONG pPos,LONG pLen),STRING,PRIVATE
SetLastError          PROCEDURE(LONG pError,STRING pText),LONG,PRIVATE
ReportProgress        PROCEDURE(STRING pStage,LONG pCompleted,LONG pTotal),PRIVATE
ReadByte              PROCEDURE(*STRING pData,LONG pPos),LONG,PRIVATE
ReadLeShort           PROCEDURE(*STRING pData,LONG pPos),LONG,PRIVATE
ReadBeShort           PROCEDURE(*STRING pData,LONG pPos),LONG,PRIVATE
ReadLeLong            PROCEDURE(*STRING pData,LONG pPos),LONG,PRIVATE
ReadBeLong            PROCEDURE(*STRING pData,LONG pPos),LONG,PRIVATE
WriteLeLong           PROCEDURE(*STRING pData,LONG pPos,LONG pValue),PRIVATE
ModLong               PROCEDURE(LONG pValue,LONG pDivisor),LONG,PRIVATE
Slice                 PROCEDURE(*STRING pData,LONG pPos,LONG pLen),STRING,PRIVATE
TpsDateToClarion      PROCEDURE(LONG pValue),LONG,PRIVATE
TpsTimeToClarion      PROCEDURE(LONG pValue),LONG,PRIVATE
                    END

! GetErrorCode equates
TpsErrSourceOpen    EQUATE(1001)
TpsErrSourceEmpty   EQUATE(1002)
TpsErrSourceRead    EQUATE(1003)
TpsErrHeaderTooShort    EQUATE(1101)
TpsErrHeaderMarker  EQUATE(1102)
TpsErrHeaderSize    EQUATE(1103)
TpsErrHeaderSignature   EQUATE(1104)
TpsErrBlockRange    EQUATE(1105)
TpsErrPageInvalid   EQUATE(1106)
TpsErrRleInvalid    EQUATE(1107)
TpsErrRecordPageInvalid EQUATE(1108)
TpsErrDecryptTooShort   EQUATE(1201)
TpsErrDecryptHeaderRange    EQUATE(1202)
TpsErrDecryptHeaderMarker   EQUATE(1203)
TpsErrDecryptSignature  EQUATE(1204)
TpsErrDecryptDataRange  EQUATE(1205)
TpsErrDecryptRangeBounds    EQUATE(1206)
TpsErrDecryptRangeAlign EQUATE(1207)
TpsErrTableIndex    EQUATE(1301)
TpsErrTableDefMissing   EQUATE(1401)
TpsErrTableDefIncomplete    EQUATE(1402)
TpsErrFieldDefHeader    EQUATE(1403)
TpsErrFieldDefBody  EQUATE(1404)
TpsErrBcdMetadata   EQUATE(1405)
TpsErrStringMetadata    EQUATE(1406)
TpsErrStringExternalName    EQUATE(1407)
TpsErrMemoExternalName  EQUATE(1408)
TpsErrMemoDef       EQUATE(1409)
TpsErrFieldDefMissing   EQUATE(1410)
TpsErrFieldDataInvalid  EQUATE(1411)
TpsErrFieldTypeUnsupported EQUATE(1412)
TpsErrFieldAmbiguous    EQUATE(1413)
TpsErrIndexDef      EQUATE(1414)
TpsErrRecordIndex   EQUATE(1501)
TpsErrRecordNotFound    EQUATE(1502)
TpsErrBlobContext   EQUATE(1601)
TpsErrBlobFieldType EQUATE(1602)
TpsErrBlobData      EQUATE(1603)

