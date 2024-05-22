# Package Index
Typing with Jython is odly defined and no index generator seems to cover it. Types are defined in a comment below each function, as close as it can be to what should be supported by mypy.

* [main](#main)
  * [BurpExtender](#main.BurpExtender)
    * [\_\_init\_\_](#main.BurpExtender.__init__)
    * [defineMetadata](#main.BurpExtender.defineMetadata)
    * [registerListeners](#main.BurpExtender.registerListeners)
    * [registerExtenderCallbacks](#main.BurpExtender.registerExtenderCallbacks)
    * [createLogEntry](#main.BurpExtender.createLogEntry)
    * [getHttpService](#main.BurpExtender.getHttpService)
    * [getRequest](#main.BurpExtender.getRequest)
    * [getResponse](#main.BurpExtender.getResponse)
    * [createMessageEditor](#main.BurpExtender.createMessageEditor)
    * [customizeUiComponents](#main.BurpExtender.customizeUiComponents)
    * [createTabs](#main.BurpExtender.createTabs)
    * [defineUI](#main.BurpExtender.defineUI)
    * [getTabCaption](#main.BurpExtender.getTabCaption)
    * [getUiComponent](#main.BurpExtender.getUiComponent)
    * [processHttpMessage](#main.BurpExtender.processHttpMessage)
    * [processProxyMessage](#main.BurpExtender.processProxyMessage)
    * [extensionUnloaded](#main.BurpExtender.extensionUnloaded)
* [ui](#ui)
  * [ui.logentry](#ui.logentry)
    * [LogEntry](#ui.logentry.LogEntry)
      * [\_\_init\_\_](#ui.logentry.LogEntry.__init__)
  * [ui.table](#ui.table)
    * [Table](#ui.table.Table)
      * [\_\_init\_\_](#ui.table.Table.__init__)
      * [changeSelection](#ui.table.Table.changeSelection)
    * [TableModel](#ui.table.TableModel)
      * [getRowCount](#ui.table.TableModel.getRowCount)
      * [getColumnCount](#ui.table.TableModel.getColumnCount)
      * [getColumnName](#ui.table.TableModel.getColumnName)
      * [getValueAt](#ui.table.TableModel.getValueAt)
* [core](#core)
  * [core.textutils](#core.textutils)
    * [normalizeString](#core.textutils.normalizeString)
  * [core.parser](#core.parser)
    * [Parser](#core.parser.Parser)
      * [\_\_init\_\_](#core.parser.Parser.__init__)
      * [parseContentType](#core.parser.Parser.parseContentType)
      * [parseCookies](#core.parser.Parser.parseCookies)
      * [parseParameters](#core.parser.Parser.parseParameters)
      * [parseRequestMessageInfo](#core.parser.Parser.parseRequestMessageInfo)
      * [parseResponseMessageInfo](#core.parser.Parser.parseResponseMessageInfo)
  * [core.fuzzer](#core.fuzzer)
    * [Fuzzer](#core.fuzzer.Fuzzer)
      * [\_\_init\_\_](#core.fuzzer.Fuzzer.__init__)
      * [createRequestFromPost](#core.fuzzer.Fuzzer.createRequestFromPost)
      * [fuzzRequestMethod](#core.fuzzer.Fuzzer.fuzzRequestMethod)

<a id="__init__"></a>

# \_\_init\_\_

<a id="main"></a>

# main

<a id="main.BurpExtender"></a>

## BurpExtender Objects

```python
class BurpExtender(IBurpExtender, IHttpListener, IProxyListener,
                   IExtensionStateListener, ITab, IMessageEditorController,
                   TableModel)
```

<a id="main.BurpExtender.__init__"></a>

#### \_\_init\_\_

```python
def __init__()
```

Defines internal config

<a id="main.BurpExtender.defineMetadata"></a>

#### defineMetadata

```python
def defineMetadata()
```

Defines metadata used by Burp (extension name)

<a id="main.BurpExtender.registerListeners"></a>

#### registerListeners

```python
def registerListeners()
```

Registers itself as a listener for IHttpListener, IProxyListener,
IExtensionStateListener

<a id="main.BurpExtender.registerExtenderCallbacks"></a>

#### registerExtenderCallbacks

```python
def registerExtenderCallbacks(callbacks)
```

Defined in IBurpExtenderCallbacks, invoked on load.
- Stores the callbacks object, an instance of IExtensionHelpers and
a stdout writer
- Registers itself as a listener for specific Burp defined events
- Defines metadata
- Defines UI

<a id="main.BurpExtender.createLogEntry"></a>

#### createLogEntry

```python
def createLogEntry(url,
                   originalMessageInfo,
                   modifiedMessageInfo,
                   toolFlag,
                   method="GET")
```

Creates a log entry in the UI

<a id="main.BurpExtender.getHttpService"></a>

#### getHttpService

```python
def getHttpService()
```

Defined in IMessageEditorController. Updates current log entry.

<a id="main.BurpExtender.getRequest"></a>

#### getRequest

```python
def getRequest()
```

Defined in IMessageEditorController. Updates current log entry.

<a id="main.BurpExtender.getResponse"></a>

#### getResponse

```python
def getResponse()
```

Defined in IMessageEditorController. Updates current log entry.

<a id="main.BurpExtender.createMessageEditor"></a>

#### createMessageEditor

```python
def createMessageEditor()
```

Creates an uneditable MessageEditor object

<a id="main.BurpExtender.customizeUiComponents"></a>

#### customizeUiComponents

```python
def customizeUiComponents(components)
```

Customizes UI components in line with Burp's UI style

<a id="main.BurpExtender.createTabs"></a>

#### createTabs

```python
def createTabs()
```

Defines tabs with original/modified request/response viewers

<a id="main.BurpExtender.defineUI"></a>

#### defineUI

```python
def defineUI()
```

Defines the UI for the extension tab. UI consists basically of a
JList containing items from the variable _issues.

<a id="main.BurpExtender.getTabCaption"></a>

#### getTabCaption

```python
def getTabCaption()
```

Defined in ITab. Defines tab caption.

<a id="main.BurpExtender.getUiComponent"></a>

#### getUiComponent

```python
def getUiComponent()
```

Defined in ITab. Defines the main UI component for the tab.

<a id="main.BurpExtender.processHttpMessage"></a>

#### processHttpMessage

```python
def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
```

Defined in IHttpListener, invoked with HTTP traffic outside proxy.
Process traffic from general HTTP listener, parses the message and if
it is a request, fuzz the request method.

<a id="main.BurpExtender.processProxyMessage"></a>

#### processProxyMessage

```python
def processProxyMessage(messageIsRequest, message)
```

Defined in IProxyListener, invoked with proxy traffic.
Process traffic from proxy, parses the message and if it is a request,
fuzz the request method.

<a id="main.BurpExtender.extensionUnloaded"></a>

#### extensionUnloaded

```python
def extensionUnloaded()
```

Defined in IExtensionStateListener, invoked on unload.
Graceful exit.

<a id="ui"></a>

# ui

<a id="ui.logentry"></a>

# ui.logentry

<a id="ui.logentry.LogEntry"></a>

## LogEntry Objects

```python
class LogEntry()
```

<a id="ui.logentry.LogEntry.__init__"></a>

#### \_\_init\_\_

```python
def __init__(tool, requestResponse, modifiedRequestResponse, url)
```

Instantiates the dataclass

<a id="ui.table"></a>

# ui.table

<a id="ui.table.Table"></a>

## Table Objects

```python
class Table(JTable)
```

<a id="ui.table.Table.__init__"></a>

#### \_\_init\_\_

```python
def __init__(extender)
```

Defines internal config

<a id="ui.table.Table.changeSelection"></a>

#### changeSelection

```python
def changeSelection(row, col, toggle, extend)
```

Shows the log entry for the selected row

<a id="ui.table.TableModel"></a>

## TableModel Objects

```python
class TableModel(AbstractTableModel)
```

<a id="ui.table.TableModel.getRowCount"></a>

#### getRowCount

```python
def getRowCount()
```

Returns the row count of the Tool/URL table

<a id="ui.table.TableModel.getColumnCount"></a>

#### getColumnCount

```python
def getColumnCount()
```

Returns the magic value `2`: column count for tool/URL columns

<a id="ui.table.TableModel.getColumnName"></a>

#### getColumnName

```python
def getColumnName(columnIndex)
```

Returns the column name based on the selected index

<a id="ui.table.TableModel.getValueAt"></a>

#### getValueAt

```python
def getValueAt(rowIndex, columnIndex)
```

Returns the table cell value based on row/column indexes: tool or URL

<a id="core"></a>

# core

<a id="core.textutils"></a>

# core.textutils

<a id="core.textutils.normalizeString"></a>

#### normalizeString

```python
def normalizeString(text)
```

Receives a raw string, normalizes unicoded chars and returns ascii

<a id="core.parser"></a>

# core.parser

<a id="core.parser.Parser"></a>

## Parser Objects

```python
class Parser()
```

<a id="core.parser.Parser.__init__"></a>

#### \_\_init\_\_

```python
def __init__(helpers, callbacks)
```

Defines internal config

<a id="core.parser.Parser.parseContentType"></a>

#### parseContentType

```python
def parseContentType(headers)
```

From a list of headers, returns the content-type, if existent

<a id="core.parser.Parser.parseCookies"></a>

#### parseCookies

```python
def parseCookies(rawCookieArr)
```

Converts an array of cookies into a dict mapping names to values

<a id="core.parser.Parser.parseParameters"></a>

#### parseParameters

```python
def parseParameters(rawParametersArr)
```

Converts an array of params into a dict mapping names to values

<a id="core.parser.Parser.parseRequestMessageInfo"></a>

#### parseRequestMessageInfo

```python
def parseRequestMessageInfo(messageInfo,
                            toolFlag=IBurpExtenderCallbacks.TOOL_PROXY)
```

Parses a messageInfo object into multiple text fields

<a id="core.parser.Parser.parseResponseMessageInfo"></a>

#### parseResponseMessageInfo

```python
def parseResponseMessageInfo(messageInfo,
                             toolFlag=IBurpExtenderCallbacks.TOOL_PROXY)
```

Parses a messageInfo object into multiple text fields

<a id="core.fuzzer"></a>

# core.fuzzer

<a id="core.fuzzer.Fuzzer"></a>

## Fuzzer Objects

```python
class Fuzzer()
```

<a id="core.fuzzer.Fuzzer.__init__"></a>

#### \_\_init\_\_

```python
def __init__(helpers, callbacks, issueHook)
```

Defines internal config

<a id="core.fuzzer.Fuzzer.createRequestFromPost"></a>

#### createRequestFromPost

```python
def createRequestFromPost(requestinfo, method="GET")
```

Receives headers from a POST request, removes POST-specific ones, changes the
method and inserts parameters

<a id="core.fuzzer.Fuzzer.fuzzRequestMethod"></a>

#### fuzzRequestMethod

```python
def fuzzRequestMethod(messageInfo, toolFlag=IBurpExtenderCallbacks.TOOL_PROXY)
```

Invoked on every intercepted HTTP request. If it is a POST request,
tries to request it again using GET.
