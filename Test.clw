  PROGRAM

  INCLUDE('TpsParser.inc'),ONCE
  INCLUDE('KEYCODES.CLW'),ONCE

TestTpsParserType   CLASS(TpsParserType),TYPE
DebugWindow           PROCEDURE(STRING pFileName)
DebugStringWindow     PROCEDURE(*STRING pValue,LONG pStart,LONG pLength,STRING pCaption),PRIVATE
DebugHexDump          PROCEDURE(*STRING pValue,LONG pLength),*STRING,PRIVATE
                    END

tp                  TestTpsParserType
Msg                 ANY
  MAP
AppendMsg   PROCEDURE(STRING pMsg,<STRING pSep>) 
  .
crlf                EQUATE('<13,10>')
comma               EQUATE(',')

TpsFileName         STRING(255)
TmpFileName         STRING(255)

TpsOwner            STRING(100)
RecoverMode         BYTE

Window              WINDOW('TPS file parser'),AT(,,506,245),AUTO,SYSTEM,FONT('Segoe UI',10)
                      PROMPT('TPS File:'),AT(5,5,,10),USE(?TpsFileName:Prompt)
                      ENTRY(@S255),AT(40,5,167,10),USE(TpsFileName)
                      BUTTON('Browse'),AT(209,5,,10),USE(?TpsFileName:browse)
                      PROMPT('Owner:'),AT(258,5,,10),USE(?TpsOwner:Prompt)
                      ENTRY(@S100),AT(289,5,95,10),USE(TpsOwner)
                      CHECK('Recover'),AT(388,5,42,10),USE(RecoverMode)
                      BUTTON('Parse'),AT(433,5,31,10),USE(?Parse),FONT(,,,FONT:bold),DEFAULT
                      BUTTON('Debug'),AT(469,5,32,10),USE(?Debug)
                      TEXT,AT(5,20,495,220),USE(?msg),SKIP,VSCROLL,FONT('Consolas'), |
                          READONLY
                    END

  CODE
  OPEN(Window)
  ACCEPT
    CASE ACCEPTED()
      OF ?TpsFileName:browse
        IF FILEDIALOG('TPS Files',TmpFileName,'(*.tps)|*.tps',FILE:KeepDir+FILE:LongName+FILE:AddExtension)
          TpsFileName = TmpFileName
        .                
      OF ?Parse
        DO Parse 
        ?msg{PROP:Text} = Msg
      OF ?Debug
        tp.DebugWindow(TpsFileName)
    .
  .
  
Parse               ROUTINE
  DATA
idxTable    LONG
idxField    LONG
idxRecords  LONG
Result  LONG
  CODE
  Msg = ''
  IF RecoverMode
    IF TpsOwner
      Result = tp.InitRecovering(TpsFileName,TpsOwner)
    ELSE
      Result = tp.InitRecovering(TpsFileName)
    .
  ELSE
    IF TpsOwner
      Result = tp.Init(TpsFileName,TpsOwner)
    ELSE
      Result = tp.Init(TpsFileName)
    .
  .
  IF Result
    AppendMsg(tp.GetError())
    EXIT
  .
  LOOP idxTable = 1 TO tp.Tables()
    AppendMsg('Table '&idxTable&' '&tp.GetTableName(idxTable),crlf)
    tp.SetTable(idxTable)
    LOOP idxField = 1 TO tp.Fields()
      AppendMsg('   '&LEFT(tp.GetFieldNameByNumber(idxField),25),crlf)
      AppendMsg(tp.GetFieldTypeByNumber(idxField),' ')
      AppendMsg(tp.GetFieldSizeByNumber(idxField),' ')
    .    
    AppendMsg(crlf)
    AppendMsg(crlf)
    LOOP idxField = 1 TO tp.Fields()
      AppendMsg(tp.GetFieldNameByNumber(idxField))
      IF idxField < tp.Fields()
        AppendMsg(comma)
      .      
    .    
    AppendMsg(crlf)
    tp.Set
    LOOP UNTIL tp.Next()
      idxRecords += 1
      IF idxRecords > 3 THEN BREAK.
      LOOP idxField = 1 TO tp.Fields()
        AppendMsg(CLIP(tp.GetFieldByNumber(idxField)))
        IF idxField < tp.Fields()
          AppendMsg(comma)
        .      
      .    
      AppendMsg(crlf)
    .    
    AppendMsg(crlf)
  .
  
AppendMsg           PROCEDURE(STRING pMsg,<STRING pSep>) 
  CODE
  IF NOT OMITTED(pSep) AND LEN(pSep) AND Msg 
    Msg = Msg & pSep
  .  
  Msg = Msg & pMsg

TestTpsParserType.DebugWindow   PROCEDURE(STRING pFileName)
TableChoiceQ                      QUEUE,PRE(DbgTable)
NameAndNo                           STRING(160)
TableIndex                          LONG
                                  END
DataViewQ                         QUEUE,PRE(DbgData)
TableNo                             LONG
RecordNumber                        LONG
PayloadLen                          LONG
Preview                             STRING(255)
SourceIndex                         LONG
                                  END
MemoViewQ                         QUEUE,PRE(DbgMemo)
TableNo                             LONG
Owner                               LONG
MemoIndex                           LONG
Sequence                            LONG
DataLen                             LONG
Arrival                             LONG
Preview                             STRING(255)
SourceIndex                         LONG
                                  END
TableDefViewQ                     QUEUE,PRE(DbgDef)
TableNo                             LONG
BlockNo                             LONG
DataLen                             LONG
Arrival                             LONG
Preview                             STRING(255)
SourceIndex                         LONG
                                  END
TableNameViewQ                    QUEUE,PRE(DbgName)
TableNo                             LONG
Name                                STRING(128)
Arrival                             LONG
SourceIndex                         LONG
                                  END
FieldViewQ                        QUEUE,PRE(DbgField)
TableNo                             LONG
FieldNo                             LONG
Name                                STRING(128)
ShortName                           STRING(128)
TypeName                            STRING(32)
Offset                              LONG
Length                              LONG
Elements                            LONG
Decimals                            LONG
BcdLength                           LONG
IsMemo                              BYTE
IsBlob                              BYTE
MemoIndex                           LONG
SourceIndex                         LONG
                                  END
I                                 LONG
J                                 LONG
CopyLen                           LONG
ViewLen                           LONG
TableCount                        LONG
PublicIndex                       LONG
LastTableNo                       LONG(-1)
SelectedTableIndex                LONG
SavedTableNo                      LONG
SrcViewPos                        LONG(1)
SrcViewLen                        LONG(8192)
SrcViewEnd                        LONG
Caption                           STRING(255)
WindowPosition                    LONG,DIM(4),STATIC
DebugWindow                       WINDOW('TPS Parser Debug'),AT(,,453,200),SYSTEM,MAX,FONT('Segoe UI',9),RESIZE
                                    SHEET,AT(1,1),FULL,USE(?DebugSheet),JOIN,NOSHEET,BELOW
                                      TAB('DataQ'),USE(?TabData)
                                        LIST,AT(5,19),FULL,USE(?ListData),VSCROLL,ALRT(MouseLeft2),FROM(DataViewQ), |
                                            FORMAT('34R(2)|M~Table No~C(0)@n_5@43R(2)|M~Record No~C(0)@n8@54R(2)|M' & |
                                            '~Payload Len~C(0)@n12@200L(2)|M~Payload Preview~@s255@'),FONT('Consolas')
                                      END
                                      TAB('MemoQ'),USE(?TabMemo)
                                        LIST,AT(5,19),FULL,USE(?ListMemo),VSCROLL,ALRT(MouseLeft2),FROM(MemoViewQ), |
                                            FORMAT('35R(2)|M~Table No~C(0)@n_5@35R(2)|M~Owner~C(0)@n-6@39R(2)|M' & |
                                            '~Memo Index~C(0)@n-8@35R(2)|M~Sequence~C(0)@n-8@45R(2)|M~Data Len~C(0)' & |
                                            '@n12@45R(2)|M~Arrival~C(0)@n12@150L(2)|M~Payload Preview~@s255@'),FONT('Consolas')
                                      END
                                      TAB('TableDefQ'),USE(?TabTableDef)
                                        LIST,AT(5,19),FULL,USE(?ListTableDef),VSCROLL,ALRT(MouseLeft2),FROM(TableDefViewQ), |
                                            FORMAT('35R(2)|M~Table No~C(0)@n_5@35R(2)|M~Block No~C(0)@n-10@45R(2)|M' & |
                                            '~Data Len~C(0)@n12@45R(2)|M~Arrival~C(0)@n12@180L(2)|M' & |
                                            '~Payload Preview~@s255@'),FONT('Consolas')
                                      END
                                      TAB('TableNameQ'),USE(?TabTableName)
                                        LIST,AT(5,19),FULL,USE(?ListTableName),VSCROLL,FROM(TableNameViewQ), |
                                            FORMAT('35R(2)|M~Table No~C(0)@n_5@200L(2)|M~Name~@s128@45R(2)|M' & |
                                            '~Arrival~C(0)@n12@'),FONT('Consolas')
                                      END
                                      TAB('FieldQ'),USE(?TabField)
                                        PROMPT('Fields for table:'),AT(5,19,,11),USE(?TableChoicePrompt)
                                        LIST,AT(77,19,183,11),USE(?TableChoice),VSCROLL,DROP(15),FROM(TableChoiceQ), |
                                            FORMAT('200L(2)'),FONT('Consolas')
                                        LIST,AT(5,35),FULL,USE(?ListField),VSCROLL,FROM(FieldViewQ), |
                                            FORMAT('24R(2)|M~Table~C(0)@n3@30R(2)|M~No.~C(0)@n5@90L(2)|M~Field Name~@s128@' & |
                                            '63L(2)|M~Short Name~@s128@45L(2)|M~Type~@s32@30R(2)|M~Offset~C(0)@n7@' & |
                                            '30R(2)|M~Length~C(0)@n7@25R(2)|M~DIM~C(0)@n6@25R(2)|M~Decimals~C(0)' & |
                                            '@n3@25R(2)|M~BCD Len~C(0)@n3@25R(2)|M~Memo~C(0)@n3@25R(2)|M~Blob~C(0)' & |
                                            '@n3@35R(2)|M~Memo Index~C(0)@n-4@'),FONT('Consolas')
                                      END
                                      TAB('Source'),USE(?TabSource)
                                        PROMPT('Loaded source bytes:'),AT(10,29),USE(?SourceInfo)
                                        ENTRY(@n11),AT(105,29,60,11),USE(SELF.SrcLen),SKIP,COLOR(COLOR:BTNFACE),READONLY
                                        PROMPT('View position:'),AT(10,48),USE(?SrcViewPosPrompt)
                                        ENTRY(@n11),AT(74,47,60,11),USE(SrcViewPos),RIGHT
                                        PROMPT('View length:'),AT(10,65),USE(?SrcViewLenPrompt)
                                        ENTRY(@n11),AT(74,64,60,11),USE(SrcViewLen),RIGHT
                                        BUTTON('View ASCII / HEX'),AT(10,84,85,18),USE(?ViewSource)
                                        PROMPT('Views are limited to 8192 bytes.'),AT(105,87),USE(?SourceLimitInfo)
                                      END
                                    END
                                  END
  CODE
  IF SELF.SrcLen = 0 AND RECORDS(SELF.DataQ) = 0 AND RECORDS(SELF.MemoQ) = 0 AND |
      RECORDS(SELF.TableDefQ) = 0 AND RECORDS(SELF.TableNameQ) = 0 AND RECORDS(SELF.FieldQ) = 0
    MESSAGE('Parse a TPS file first. No source or partial queue data is available.','TPS Parser Debug')
    RETURN
  END

  SavedTableNo = SELF.CurrentTable
  DO LoadTableChoices
  IF SelectedTableIndex > 0
    SELF.SetTable(SelectedTableIndex)
  END
  DO LoadStaticViews
  DO LoadFields

  OPEN(DebugWindow)
  IF WindowPosition[4]
    SETPOSITION(0,WindowPosition[1],WindowPosition[2],WindowPosition[3],WindowPosition[4])
  END
  0{PROP:Text} = 'TPS Parser Debug - ' & CLIP(pFileName)
  ?TabData{PROP:Text} = 'DataQ (' & RECORDS(DataViewQ) & ')'
  ?TabMemo{PROP:Text} = 'MemoQ (' & RECORDS(MemoViewQ) & ')'
  ?TabTableDef{PROP:Text} = 'TableDefQ (' & RECORDS(TableDefViewQ) & ')'
  ?TabTableName{PROP:Text} = 'TableNameQ (' & RECORDS(TableNameViewQ) & ')'
  ?TabField{PROP:Text} = 'FieldQ (' & RECORDS(FieldViewQ) & ')'
  IF SelectedTableIndex > 0
    ?TableChoice{PROP:Selected} = SelectedTableIndex
  ELSE
    DISABLE(?TableChoice)
  END

  ACCEPT
    CASE EVENT()
      OF EVENT:AlertKey
        IF KEYCODE() = MouseLeft2
          CASE FIELD()
            OF ?ListData
              GET(DataViewQ,CHOICE(?ListData))
              IF ~ERRORCODE()
                GET(SELF.DataQ,DbgData:SourceIndex)
                IF ~ERRORCODE() AND NOT (SELF.DataQ.Payload &= NULL) AND SELF.DataQ.PayloadLen > 0
                  ViewLen = SELF.DataQ.PayloadLen
                  IF ViewLen > SIZE(SELF.DataQ.Payload)
                    ViewLen = SIZE(SELF.DataQ.Payload)
                  END
                  IF ViewLen > 8192
                    ViewLen = 8192
                  END
                  Caption = 'DataQ row ' & DbgData:SourceIndex & ' payload length ' & SELF.DataQ.PayloadLen
                  IF ViewLen < SELF.DataQ.PayloadLen
                    Caption = CLIP(Caption) & ' (showing first ' & ViewLen & ')'
                  END
                  SELF.DebugStringWindow(SELF.DataQ.Payload,1,ViewLen,Caption)
                END
              END
            OF ?ListMemo
              GET(MemoViewQ,CHOICE(?ListMemo))
              IF ~ERRORCODE()
                GET(SELF.MemoQ,DbgMemo:SourceIndex)
                IF ~ERRORCODE() AND NOT (SELF.MemoQ.Payload &= NULL) AND SELF.MemoQ.DataLen > 0
                  ViewLen = SELF.MemoQ.DataLen
                  IF ViewLen > SIZE(SELF.MemoQ.Payload)
                    ViewLen = SIZE(SELF.MemoQ.Payload)
                  END
                  IF ViewLen > 8192
                    ViewLen = 8192
                  END
                  Caption = 'MemoQ row ' & DbgMemo:SourceIndex & ' payload length ' & SELF.MemoQ.DataLen
                  IF ViewLen < SELF.MemoQ.DataLen
                    Caption = CLIP(Caption) & ' (showing first ' & ViewLen & ')'
                  END
                  SELF.DebugStringWindow(SELF.MemoQ.Payload,1,ViewLen,Caption)
                END
              END
            OF ?ListTableDef
              GET(TableDefViewQ,CHOICE(?ListTableDef))
              IF ~ERRORCODE()
                GET(SELF.TableDefQ,DbgDef:SourceIndex)
                IF ~ERRORCODE() AND NOT (SELF.TableDefQ.Payload &= NULL) AND SELF.TableDefQ.DataLen > 0
                  ViewLen = SELF.TableDefQ.DataLen
                  IF ViewLen > SIZE(SELF.TableDefQ.Payload)
                    ViewLen = SIZE(SELF.TableDefQ.Payload)
                  END
                  IF ViewLen > 8192
                    ViewLen = 8192
                  END
                  Caption = 'TableDefQ row ' & DbgDef:SourceIndex & ' payload length ' & SELF.TableDefQ.DataLen
                  IF ViewLen < SELF.TableDefQ.DataLen
                    Caption = CLIP(Caption) & ' (showing first ' & ViewLen & ')'
                  END
                  SELF.DebugStringWindow(SELF.TableDefQ.Payload,1,ViewLen,Caption)
                END
              END
          END
        END
    END

    CASE ACCEPTED()
      OF ?TableChoice
        GET(TableChoiceQ,CHOICE(?TableChoice))
        IF ~ERRORCODE() AND SELF.SetTable(DbgTable:TableIndex) = 0
          SelectedTableIndex = DbgTable:TableIndex
          DO LoadFields
          ?TabField{PROP:Text} = 'FieldQ (' & RECORDS(FieldViewQ) & ')'
          DISPLAY(?ListField)
        END
      OF ?ViewSource
        IF SELF.SrcLen <= 0 OR (SELF.Src &= NULL)
          MESSAGE('No loaded source is available.','TPS Parser Debug')
          CYCLE
        END
        IF SrcViewPos < 1
          SrcViewPos = 1
        END
        IF SrcViewPos > SELF.SrcLen
          SrcViewPos = SELF.SrcLen
        END
        IF SrcViewLen < 1
          SrcViewLen = 1
        END
        IF SrcViewLen > 8192
          SrcViewLen = 8192
        END
        SrcViewEnd = SrcViewPos + SrcViewLen - 1
        IF SrcViewEnd > SELF.SrcLen
          SrcViewEnd = SELF.SrcLen
          SrcViewLen = SrcViewEnd - SrcViewPos + 1
        END
        DISPLAY
        Caption = 'Source length ' & SELF.SrcLen & ', bytes ' & SrcViewPos & ' through ' & SrcViewEnd
        SELF.DebugStringWindow(SELF.Src,SrcViewPos,SrcViewLen,Caption)
    END
  END
  GETPOSITION(0,WindowPosition[1],WindowPosition[2],WindowPosition[3],WindowPosition[4])
  CLOSE(DebugWindow)
  RETURN

LoadTableChoices    ROUTINE
  FREE(TableChoiceQ)
  TableCount = SELF.Tables()
  SelectedTableIndex = CHOOSE(TableCount > 0,1,0)
  LastTableNo = -1
  PublicIndex = 0
  LOOP I = 1 TO RECORDS(SELF.TableDefQ)
    GET(SELF.TableDefQ,I)
    IF SELF.TableDefQ.TableNo <> LastTableNo
      LastTableNo = SELF.TableDefQ.TableNo
      PublicIndex += 1
      IF LastTableNo = SavedTableNo
        SelectedTableIndex = PublicIndex
      END
    END
  END
  LOOP I = 1 TO TableCount
    CLEAR(TableChoiceQ)
    DbgTable:TableIndex = I
    DbgTable:NameAndNo = CLIP(SELF.GetTableName(I)) & ' (' & I & ')'
    ADD(TableChoiceQ)
  END

LoadStaticViews     ROUTINE
  FREE(DataViewQ)
  LOOP I = 1 TO RECORDS(SELF.DataQ)
    GET(SELF.DataQ,I)
    CLEAR(DataViewQ)
    DbgData:TableNo = SELF.DataQ.TableNo
    DbgData:RecordNumber = SELF.DataQ.RecordNumber
    DbgData:PayloadLen = SELF.DataQ.PayloadLen
    DbgData:SourceIndex = I
    IF NOT (SELF.DataQ.Payload &= NULL) AND SELF.DataQ.PayloadLen > 0
      CopyLen = SELF.DataQ.PayloadLen
      IF CopyLen > SIZE(SELF.DataQ.Payload)
        CopyLen = SIZE(SELF.DataQ.Payload)
      END
      IF CopyLen > SIZE(DbgData:Preview)
        CopyLen = SIZE(DbgData:Preview)
      END
      IF CopyLen > 0
        DbgData:Preview[1 : CopyLen] = SELF.DataQ.Payload[1 : CopyLen]
        LOOP J = 1 TO CopyLen
          IF VAL(DbgData:Preview[J]) < 32 OR VAL(DbgData:Preview[J]) = 127
            DbgData:Preview[J] = '.'
          END
        END
      END
    END
    ADD(DataViewQ)
  END

  FREE(MemoViewQ)
  LOOP I = 1 TO RECORDS(SELF.MemoQ)
    GET(SELF.MemoQ,I)
    CLEAR(MemoViewQ)
    DbgMemo:TableNo = SELF.MemoQ.TableNo
    DbgMemo:Owner = SELF.MemoQ.Owner
    DbgMemo:MemoIndex = SELF.MemoQ.MemoIndex
    DbgMemo:Sequence = SELF.MemoQ.Sequence
    DbgMemo:DataLen = SELF.MemoQ.DataLen
    DbgMemo:Arrival = SELF.MemoQ.Arrival
    DbgMemo:SourceIndex = I
    IF NOT (SELF.MemoQ.Payload &= NULL) AND SELF.MemoQ.DataLen > 0
      CopyLen = SELF.MemoQ.DataLen
      IF CopyLen > SIZE(SELF.MemoQ.Payload)
        CopyLen = SIZE(SELF.MemoQ.Payload)
      END
      IF CopyLen > SIZE(DbgMemo:Preview)
        CopyLen = SIZE(DbgMemo:Preview)
      END
      IF CopyLen > 0
        DbgMemo:Preview[1 : CopyLen] = SELF.MemoQ.Payload[1 : CopyLen]
        LOOP J = 1 TO CopyLen
          IF VAL(DbgMemo:Preview[J]) < 32 OR VAL(DbgMemo:Preview[J]) = 127
            DbgMemo:Preview[J] = '.'
          END
        END
      END
    END
    ADD(MemoViewQ)
  END

  FREE(TableDefViewQ)
  LOOP I = 1 TO RECORDS(SELF.TableDefQ)
    GET(SELF.TableDefQ,I)
    CLEAR(TableDefViewQ)
    DbgDef:TableNo = SELF.TableDefQ.TableNo
    DbgDef:BlockNo = SELF.TableDefQ.BlockNo
    DbgDef:DataLen = SELF.TableDefQ.DataLen
    DbgDef:Arrival = SELF.TableDefQ.Arrival
    DbgDef:SourceIndex = I
    IF NOT (SELF.TableDefQ.Payload &= NULL) AND SELF.TableDefQ.DataLen > 0
      CopyLen = SELF.TableDefQ.DataLen
      IF CopyLen > SIZE(SELF.TableDefQ.Payload)
        CopyLen = SIZE(SELF.TableDefQ.Payload)
      END
      IF CopyLen > SIZE(DbgDef:Preview)
        CopyLen = SIZE(DbgDef:Preview)
      END
      IF CopyLen > 0
        DbgDef:Preview[1 : CopyLen] = SELF.TableDefQ.Payload[1 : CopyLen]
        LOOP J = 1 TO CopyLen
          IF VAL(DbgDef:Preview[J]) < 32 OR VAL(DbgDef:Preview[J]) = 127
            DbgDef:Preview[J] = '.'
          END
        END
      END
    END
    ADD(TableDefViewQ)
  END

  FREE(TableNameViewQ)
  LOOP I = 1 TO RECORDS(SELF.TableNameQ)
    GET(SELF.TableNameQ,I)
    CLEAR(TableNameViewQ)
    DbgName:TableNo = SELF.TableNameQ.TableNo
    DbgName:Arrival = SELF.TableNameQ.Arrival
    DbgName:SourceIndex = I
    IF ~SELF.TableNameQ.Name &= NULL
      DbgName:Name = SELF.TableNameQ.Name
    END
    ADD(TableNameViewQ)
  END

LoadFields          ROUTINE
  FREE(FieldViewQ)
  LOOP I = 1 TO RECORDS(SELF.FieldQ)
    GET(SELF.FieldQ,I)
    CLEAR(FieldViewQ)
    DbgField:TableNo = SELF.FieldQ.TableNo
    DbgField:FieldNo = SELF.FieldQ.FieldNo
    IF ~SELF.FieldQ.Name &= NULL
      DbgField:Name = SELF.FieldQ.Name
    END
    IF ~SELF.FieldQ.ShortName &= NULL
      DbgField:ShortName = SELF.FieldQ.ShortName
    END
    DbgField:TypeName = SELF.FieldQ.TypeName
    DbgField:Offset = SELF.FieldQ.Offset
    DbgField:Length = SELF.FieldQ.Length
    DbgField:Elements = SELF.FieldQ.Elements
    DbgField:Decimals = SELF.FieldQ.BcdDigitsAfterDecimal
    DbgField:BcdLength = SELF.FieldQ.BcdLengthOfElement
    DbgField:IsMemo = SELF.FieldQ.IsMemo
    DbgField:IsBlob = SELF.FieldQ.IsBlob
    DbgField:MemoIndex = SELF.FieldQ.MemoIndex
    DbgField:SourceIndex = I
    ADD(FieldViewQ)
  END

TestTpsParserType.DebugStringWindow PROCEDURE(*STRING pValue,LONG pStart,LONG pLength,STRING pCaption)
DisplayValue                          &STRING
HexText                               &STRING
ShowHex                               BYTE(1),STATIC
HScrollText                           BYTE(1),STATIC
VScrollText                           BYTE(1),STATIC
ValueEnd                              LONG
WindowPosition                        LONG,DIM(4),STATIC
StringWindow                          WINDOW('String Value'),AT(,,310,170),SYSTEM,MAX,FONT('Segoe UI',9),RESIZE
                                        TOOLBAR,AT(0,0,325),USE(?StringToolbar)
                                          CHECK('Show HEX'),AT(2,0),USE(ShowHex),TIP('Show the value in hexadecimal')
                                          CHECK('HScroll'),AT(74,0),USE(HScrollText)
                                          CHECK('VScroll'),AT(126,0),USE(VScrollText)
                                        END
                                        TEXT,AT(0,2),FULL,USE(?TextValue),HVSCROLL,READONLY,FLAT,FONT('Consolas')
                                        TEXT,AT(0,2),FULL,USE(?HexValue),HIDE,HVSCROLL,READONLY,FLAT,FONT('Consolas')
                                      END
  CODE
  IF pLength < 1 OR pStart < 1 OR pStart > SIZE(pValue)
    MESSAGE('No data is available for this view.','TPS Parser Debug')
    RETURN
  END
  ValueEnd = pStart + pLength - 1
  IF ValueEnd > SIZE(pValue)
    ValueEnd = SIZE(pValue)
    pLength = ValueEnd - pStart + 1
  END
  DisplayValue &= NEW(STRING(pLength))
  IF DisplayValue &= NULL
    MESSAGE('Could not allocate the debug display buffer.','TPS Parser Debug')
    RETURN
  END
  DisplayValue = pValue[pStart : ValueEnd]

  OPEN(StringWindow)
  IF WindowPosition[4]
    SETPOSITION(0,WindowPosition[1],WindowPosition[2],WindowPosition[3],WindowPosition[4])
  END
  ?TextValue{PROP:Use} = DisplayValue
  ?TextValue{PROP:HScroll} = HScrollText
  ?TextValue{PROP:VScroll} = VScrollText
  0{PROP:Text} = CLIP(pCaption) & ' - displayed length ' & pLength
  IF ShowHex
    POST(EVENT:Accepted,?ShowHex)
  END

  ACCEPT
    CASE ACCEPTED()
      OF ?HScrollText
        ?TextValue{PROP:HScroll} = HScrollText
      OF ?VScrollText
        ?TextValue{PROP:VScroll} = VScrollText
      OF ?ShowHex
        IF HexText &= NULL
          HexText &= SELF.DebugHexDump(DisplayValue,pLength)
          IF ~HexText &= NULL
            ?HexValue{PROP:Use} = HexText
          END
        END
        IF ShowHex AND (HexText &= NULL)
          ShowHex = FALSE
          MESSAGE('Could not allocate the hexadecimal display buffer.','TPS Parser Debug')
        END
        ?TextValue{PROP:Hide} = ShowHex
        ?HexValue{PROP:Hide} = 1 - ShowHex
    END
  END
  GETPOSITION(0,WindowPosition[1],WindowPosition[2],WindowPosition[3],WindowPosition[4])
  CLOSE(StringWindow)
  IF ~HexText &= NULL
    DISPOSE(HexText)
  END
  DISPOSE(DisplayValue)

TestTpsParserType.DebugHexDump  PROCEDURE(*STRING pValue,LONG pLength)
Dump                              &STRING
DumpPosition                      LONG
Line                              GROUP,PRE()
                                    STRING('<13,10>')
Offset                              STRING('Offset ')
Hex                                 STRING(' 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16  ')
HexByte                             STRING(3),DIM(16),OVER(Hex)
Ascii                               STRING('0123456789abcdef')
                                  END
LineSize                          LONG
Value                             BYTE
Position                          LONG
Column                            LONG
HexDigits                         STRING('0123456789ABCDEF')
  CODE
  IF pLength < 1
    RETURN NULL
  END
  IF pLength > SIZE(pValue)
    pLength = SIZE(pValue)
  END
  LineSize = SIZE(Line)
  Dump &= NEW(STRING((2 + INT(pLength / 16)) * LineSize))
  IF Dump &= NULL
    RETURN NULL
  END
  Dump[1 : LineSize] = SUB(Line,3,LineSize)
  DumpPosition = LineSize - 1
  LOOP Position = 0 TO pLength - 1 BY 16
    Offset = Position
    Hex = ''
    Ascii = ''
    LOOP Column = 1 TO 16
      IF Position + Column > pLength
        BREAK
      END
      Value = VAL(pValue[Position + Column])
      IF Value >= 32 AND Value <> 127
        Ascii[Column] = CHR(Value)
      ELSE
        Ascii[Column] = '.'
      END
      HexByte[Column,1] = HexDigits[BSHIFT(Value,-4) + 1]
      HexByte[Column,2] = HexDigits[BAND(Value,0FH) + 1]
    END
    Dump[DumpPosition : DumpPosition + LineSize - 1] = Line
    DumpPosition += LineSize
  END
  RETURN Dump
