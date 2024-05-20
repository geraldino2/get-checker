from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IExtensionStateListener
from burp import IBurpExtenderCallbacks
from burp import IMessageEditorController
from burp import ITab
from java.io import PrintWriter
from javax.swing import JList, JScrollPane, BoxLayout, JTabbedPane, JSplitPane
from java.util import ArrayList
from threading import Lock
from ui.table import Table, TableModel
from core.fuzzer import Fuzzer
from ui.logentry import LogEntry

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener, ITab, IMessageEditorController, TableModel):
    def __init__(self):
        # type: () -> None
        """Defines config"""
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

    def	registerExtenderCallbacks(self, callbacks):
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
            callbacks = self._callbacks,
            helpers = self._helpers,
            issueHook = self.createIssue
        )
        self.registerListeners()

        self.defineMetadata()

        self.defineUI()
    
    def createIssue(self, url, originalMessageInfo, modifiedMessageInfo, toolFlag, verb = "GET"):
        # type: (Tuple[str, str]) -> None
        """Creates a log entry in the UI"""
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(originalMessageInfo), self._callbacks.saveBuffersToTempFiles(modifiedMessageInfo), url))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    def defineUI(self):
        # type: () -> None
        """
        Defines the UI for the extension tab. UI consists basically of a 
        JList containing items from the variable _issues.
        """
        # main split pane
        self._main_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._main_panel.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        self._modifiedRequestViewer = self._callbacks.createMessageEditor(self, False)
        self._modifiedResponseViewer = self._callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        tabs.addTab("Modified request", self._modifiedRequestViewer.getComponent())
        tabs.addTab("Modified response", self._modifiedResponseViewer.getComponent())
        self._main_panel.setRightComponent(tabs)
        
        # customize our UI components
        self._callbacks.customizeUiComponent(self._main_panel)
        self._callbacks.customizeUiComponent(logTable)
        self._callbacks.customizeUiComponent(scrollPane)
        self._callbacks.customizeUiComponent(tabs)

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
        it is a request, fuzz the request verb. 
        """
        if messageIsRequest:
            pass
        else:
            self.fuzzer.fuzzRequestVerb(messageInfo, toolFlag)

    def processProxyMessage(self, messageIsRequest, message):
        # type: (boolean, IInterceptedProxyMessage) -> None
        """
        Defined in IProxyListener, invoked with proxy traffic.
        Process traffic from proxy, parses the message and if it is a request,
        fuzz the request verb.
        """
        if messageIsRequest:
            pass
        else:
            self.fuzzer.fuzzRequestVerb(message.getMessageInfo())

    def extensionUnloaded(self):
        # type: () -> None
        """
        Defined in IExtensionStateListener, invoked on unload.
        Graceful exit.
        """
        self._stdout.println("Extension was unloaded")
