from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IExtensionStateListener
from burp import IMessageEditorController
from burp import ITab
from java.io import PrintWriter
from javax.swing import JScrollPane, JTabbedPane, JSplitPane
from java.util import ArrayList
from threading import Lock
from ui.table import Table, TableModel
from core.fuzzer import Fuzzer
from ui.logentry import LogEntry


class BurpExtender(
    IBurpExtender,
    IHttpListener,
    IProxyListener,
    IExtensionStateListener,
    ITab,
    IMessageEditorController,
    TableModel,
):
    def __init__(self):
        # type: () -> None
        """Defines internal config"""
        self.EXT_NAME = "GET Checker"
        self._log = ArrayList()
        self._lock = Lock()

    def defineMetadata(self):
        # type: () -> None
        """Defines metadata used by Burp (extension name)"""
        self._callbacks.setExtensionName(self.EXT_NAME)

    def registerListeners(self):
        # type: () -> None
        """
        Registers itself as a listener for IHttpListener, IProxyListener,
        IExtensionStateListener
        """
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerProxyListener(self)
        self._callbacks.registerExtensionStateListener(self)

    def registerExtenderCallbacks(self, callbacks):
        # type: (IBurpExtenderCallbacks) -> None
        """
        Defined in IBurpExtenderCallbacks, invoked on load.
        - Stores the callbacks object, an instance of IExtensionHelpers and
        a stdout writer
        - Registers itself as a listener for specific Burp defined events
        - Defines metadata
        - Defines UI
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self.fuzzer = Fuzzer(
            callbacks=self._callbacks,
            helpers=self._helpers,
            issueHook=self.createLogEntry,
        )
        self.registerListeners()

        self.defineMetadata()

        self.defineUI()

    def createLogEntry(
        self, url, originalMessageInfo, modifiedMessageInfo, toolFlag, method="GET"
    ):
        # type: (str, IHttpRequestResponse, IHttpRequestResponse, int, str) -> None
        """Creates a log entry in the UI"""
        with self._lock:
            logEntry = LogEntry(
                tool=toolFlag,
                requestResponse=self._callbacks.saveBuffersToTempFiles(
                    originalMessageInfo
                ),
                modifiedRequestResponse=self._callbacks.saveBuffersToTempFiles(
                    modifiedMessageInfo
                ),
                url=url,
            )
            self._log.add(logEntry)
            self.fireTableRowsInserted(
                self._log.size(), self._log.size()
            )  # required by AbstractTableModel to update the table in UI

    def getHttpService(self):
        # type: () -> IHttpService
        """Defined in IMessageEditorController. Updates current log entry."""
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        # type: () -> byte[]
        """Defined in IMessageEditorController. Updates current log entry."""
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        # type: () -> byte[]
        """Defined in IMessageEditorController. Updates current log entry."""
        return self._currentlyDisplayedItem.getResponse()

    def createMessageEditor(self):
        # type: () -> IMessageEditor
        """Creates an uneditable MessageEditor object"""
        return self._callbacks.createMessageEditor(self, False)

    def customizeUiComponents(self, components):
        # type: (List[java.awt.Component]) -> None
        """Customizes UI components in line with Burp's UI style"""
        for component in components:
            self._callbacks.customizeUiComponent(component)

    def createTabs(self):
        # type: () -> None
        """Defines tabs with original/modified request/response viewers"""
        tabs = JTabbedPane()
        self._requestViewer = self.createMessageEditor()
        self._responseViewer = self.createMessageEditor()
        self._modifiedRequestViewer = self.createMessageEditor()
        self._modifiedResponseViewer = self.createMessageEditor()
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        tabs.addTab("Modified request", self._modifiedRequestViewer.getComponent())
        tabs.addTab("Modified response", self._modifiedResponseViewer.getComponent())
        self._main_panel.setRightComponent(tabs)
        self.customizeUiComponents([tabs])

    def defineUI(self):
        # type: () -> None
        """
        Defines the UI for the extension tab. UI consists basically of a
        JList containing items from the variable _issues.
        """
        self._main_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._main_panel.setLeftComponent(scrollPane)
        self.createTabs()

        self.customizeUiComponents([self._main_panel, logTable, scrollPane])

        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        # type: () -> str
        """Defined in ITab. Defines tab caption."""
        return self.EXT_NAME

    def getUiComponent(self):
        # type: () -> java.awt.Component
        """Defined in ITab. Defines the main UI component for the tab."""
        return self._main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # type: (int, boolean, IHttpRequestResponse) -> None
        """
        Defined in IHttpListener, invoked with HTTP traffic outside proxy.
        Process traffic from general HTTP listener, parses the message and if
        it is a request, fuzz the request method.
        """
        if messageIsRequest:
            pass
        else:
            self.fuzzer.fuzzRequestMethod(messageInfo, toolFlag)

    def processProxyMessage(self, messageIsRequest, message):
        # type: (boolean, IInterceptedProxyMessage) -> None
        """
        Defined in IProxyListener, invoked with proxy traffic.
        Process traffic from proxy, parses the message and if it is a request,
        fuzz the request method.
        """
        if messageIsRequest:
            pass
        else:
            self.fuzzer.fuzzRequestMethod(message.getMessageInfo())

    def extensionUnloaded(self):
        # type: () -> None
        """
        Defined in IExtensionStateListener, invoked on unload.
        Graceful exit.
        """
        self._stdout.println("Extension was unloaded")
