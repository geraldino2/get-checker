from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IExtensionStateListener
from burp import IBurpExtenderCallbacks
from burp import ITab
from core.piiscanner import PIIScanner
from collections import defaultdict
from java.io import PrintWriter
from javax.swing import JPanel, JLabel, JList, JScrollPane, BoxLayout

CONSUMER = PIIScanner()

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener, ITab):
    def __init__(self):
        # type: () -> None
        """Defines config"""
        self.consumer = CONSUMER

    def defineMetadata(self):
        # type: () -> None
        """Defines metadata used by Burp (extension name)"""
        self._callbacks.setExtensionName(self.consumer.EXT_NAME)

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
        
        self.registerListeners()

        self.defineMetadata()

        self.defineUI()
    
    def defineUI(self):
        # type: () -> None
        """
        Defines the UI for the extension tab. UI consists basically of a 
        JList containing items from the consumer variable _issues.
        """
        self._main_panel = JPanel()
        self._main_panel.setLayout(
            BoxLayout(self._main_panel, BoxLayout.Y_AXIS)
        )
        self._main_panel.add(JLabel("Issue list"))
        self._scroll_pane = JScrollPane(JList(self.consumer._issues))
        self._main_panel.add(self._scroll_pane)

        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        # type: () -> str
        """Defined in ITab. Defines tab caption."""
        return self.consumer.EXT_NAME

    def getUiComponent(self):
        # type: () -> java.awt.Component
        """Defined in ITab. Defines the main UI component for the tab."""
        return self._main_panel

    def parseCookies(self, rawCookieArr):
        # type: (List[ICookie]) -> Dict[str, Set[str]]
        """Converts an array of cookies into a dict mapping names to values"""
        cookies = defaultdict(set)
        for rawCookie in rawCookieArr:
            cookies[rawCookie.getName()].add(rawCookie.getValue())
        return dict(cookies)

    def parseResponseMessageInfo(self, messageInfo, toolFlag = IBurpExtenderCallbacks.TOOL_PROXY):
        # type: (IHttpRequestResponse, int) -> Tuple[str, str, str, int, str, Dict[str, Set[str]], List[str]]
        """Parses a messageInfo object into multiple text fields"""
        httpResponse = messageInfo.getResponse()
        parsedResponse = self._helpers.analyzeResponse(httpResponse)
        requestInfo = self._helpers.analyzeRequest(messageInfo)

        source = self._callbacks.getToolName(toolFlag)
        method = requestInfo.getMethod()
        url = str(requestInfo.getUrl()) # getUrl returns a java.net.URL object
        status = parsedResponse.getStatusCode()
        bodyOffset = parsedResponse.getBodyOffset()
        body = self._helpers.bytesToString(httpResponse[bodyOffset:])
        cookies = self.parseCookies(parsedResponse.getCookies())
        headers = parsedResponse.getHeaders()
        return source, method, url, status, body, cookies, headers

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # type: (int, boolean, IHttpRequestResponse) -> None
        """
        Defined in IHttpListener, invoked with HTTP traffic outside proxy.
        Process traffic from general HTTP listener, parses the message if it is 
        a response and forwards it to a consumer. 
        """
        if messageIsRequest:
            pass
        else:
            self.consumer.treatResponse(
                *self.parseResponseMessageInfo(
                    messageInfo,
                    toolFlag
                )
            )

    def processProxyMessage(self, messageIsRequest, message):
        # type: (boolean, IInterceptedProxyMessage) -> None
        """
        Defined in IProxyListener, invoked with proxy traffic.
        Process traffic from proxy, parses the message if it is a response
        and forwards it to a consumer. 
        """
        if messageIsRequest:
            pass
        else:
            messageInfo = message.getMessageInfo()
            self.consumer.treatResponse(
                *self.parseResponseMessageInfo(messageInfo)
            )

    def extensionUnloaded(self):
        # type: () -> None
        """
        Defined in IExtensionStateListener, invoked on unload.
        Graceful exit.
        """
        self._stdout.println("Extension was unloaded")
