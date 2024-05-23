# Package Index
Typing with Jython is odly defined and no index generator seems to cover it. Types are defined in a comment below each function, as close as it can be to what should be supported by mypy.

* [main](#main)
  * [BurpExtender](#main.BurpExtender)
    * [\_\_init\_\_](#main.BurpExtender.__init__)
    * [defineMetadata](#main.BurpExtender.defineMetadata)
    * [callbacksRegister](#main.BurpExtender.callbacksRegister)
    * [registerExtenderCallbacks](#main.BurpExtender.registerExtenderCallbacks)
    * [createMenuItems](#main.BurpExtender.createMenuItems)
    * [sendInvocationToScanner](#main.BurpExtender.sendInvocationToScanner)
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
  * [core.scanner](#core.scanner)
    * [Scanner](#core.scanner.Scanner)
      * [\_\_init\_\_](#core.scanner.Scanner.__init__)
      * [updateRequestWithParam](#core.scanner.Scanner.updateRequestWithParam)
      * [generateXssRequests](#core.scanner.Scanner.generateXssRequests)
      * [probeXss](#core.scanner.Scanner.probeXss)
      * [scanRequest](#core.scanner.Scanner.scanRequest)
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
  * [core.webdriverxss](#core.webdriverxss)
    * [getWebdriver](#core.webdriverxss.getWebdriver)
    * [verifyXss](#core.webdriverxss.verifyXss)

<a id="__init__"></a>

# \_\_init\_\_

<a id="main"></a>

# main

<a id="main.BurpExtender"></a>

## BurpExtender Objects

```python
class BurpExtender(IBurpExtender, IExtensionStateListener, ITab,
                   IMessageEditorController, IContextMenuFactory, TableModel)
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

<a id="main.BurpExtender.callbacksRegister"></a>

#### callbacksRegister

```python
def callbacksRegister()
```

Registers itself as a listener for IExtensionStateListener and as
IContextMenuFactory

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

<a id="main.BurpExtender.createMenuItems"></a>

#### createMenuItems

```python
def createMenuItems(invocation)
```

Defined in IContextMenuFactory, defines the UI menu items on request right
click and the actions to be performed when clicked

<a id="main.BurpExtender.sendInvocationToScanner"></a>

#### sendInvocationToScanner

```python
def sendInvocationToScanner(invocation)
```

Receives requests from the context menu and sends them to the scanner in a new
thread

<a id="main.BurpExtender.createLogEntry"></a>

#### createLogEntry

```python
def createLogEntry(url, originalMessageInfo, modifiedMessageInfo, paramName)
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
def __init__(param, requestResponse, modifiedRequestResponse, url)
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

Returns the row count of the Param/URL table

<a id="ui.table.TableModel.getColumnCount"></a>

#### getColumnCount

```python
def getColumnCount()
```

Returns the magic value `2`: column count for param/URL columns

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

Returns the table cell value based on row/column indexes: param or URL

<a id="core"></a>

# core

<a id="core.scanner"></a>

# core.scanner

<a id="core.scanner.Scanner"></a>

## Scanner Objects

```python
class Scanner()
```

<a id="core.scanner.Scanner.__init__"></a>

#### \_\_init\_\_

```python
def __init__(helpers, callbacks, issueHook)
```

Defines internal config

<a id="core.scanner.Scanner.updateRequestWithParam"></a>

#### updateRequestWithParam

```python
def updateRequestWithParam(request, parameter)
```

Receives a request and an existing parameter, updates the parameter value

<a id="core.scanner.Scanner.generateXssRequests"></a>

#### generateXssRequests

```python
def generateXssRequests(request, requestInfo)
```

Receives a request and a tuple with request information, inserts XSS payloads
for each parameter and creates a modified request with the payload. Returns
len(payloads)*len(parameters) requests (one for each payload-parameter pair)

<a id="core.scanner.Scanner.probeXss"></a>

#### probeXss

```python
def probeXss(originalMessageInfo, request, webdriver)
```

Sends a request with an XSS payload, using Burp and Selenium (for DOM XSS),
waits for the response and checks if the payload is executed. If it is, creates
an issue

<a id="core.scanner.Scanner.scanRequest"></a>

#### scanRequest

```python
def scanRequest(messageInfo)
```

Invoked on every request sent from the context menu. Iterates through valid
parameters, one by one, changes their value to an XSS payload, sends a request,
waits for script execution and creates an issue if the payload is executed

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

<a id="core.webdriverxss"></a>

# core.webdriverxss

<a id="core.webdriverxss.getWebdriver"></a>

#### getWebdriver

```python
def getWebdriver()
```

Returns a configured Chrome WebDriver instance

<a id="core.webdriverxss.verifyXss"></a>

#### verifyXss

```python
def verifyXss(webdriver, url)
```

Verifies if an XSS (DOM, reflected) vulnerability exists for the given request

