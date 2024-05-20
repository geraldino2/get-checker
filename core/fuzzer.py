from burp import IBurpExtenderCallbacks
from java.util import ArrayList
from parser import Parser


class Fuzzer:
    def __init__(self, helpers, callbacks, issueHook):
        # type: (IExtensionHelpers, IBurpExtenderCallbacks, function) -> None
        """Defines internal config"""
        self._helpers = helpers
        self._callbacks = callbacks
        self.parser = Parser(self._helpers, self._callbacks)
        self.newIssueHook = issueHook

    def createRequestFromPost(self, headers, method="GET"):
        # type: (java.util.ArrayList) -> byte[]
        """
        Receives headers from a POST request, removes POST-specific ones and changes
        the method
        """
        modifiedHeaders = ArrayList(headers)
        modifiedRequestLine = method + modifiedHeaders.get(0)[4:]
        modifiedHeaders.set(0, modifiedRequestLine)
        postOnlyHeaders = ["Content-Type", "Content-Length"]
        modifiedHeaders = [
            header
            for header in modifiedHeaders
            if not any(header.startswith(h) for h in postOnlyHeaders)
        ]

        emptyBodyRequest = self._helpers.buildHttpMessage(modifiedHeaders, "")
        return emptyBodyRequest

    def fuzzRequestMethod(
        self, messageInfo, toolFlag=IBurpExtenderCallbacks.TOOL_PROXY
    ):
        # type: (IHttpRequestResponse, int) -> None
        """
        Invoked on every intercepted HTTP request. If it is a POST request,
        tries to request it again using GET.
        """
        requestInfo = self.parser.parseRequestMessageInfo(messageInfo, toolFlag)

        if requestInfo.method == "POST":
            newRequest = self.createRequestFromPost(requestInfo.headers)
            modifiedRequestResponse = self._callbacks.makeHttpRequest(
                messageInfo.getHttpService(), newRequest
            )
            parsedModifiedResponse = self.parser.parseResponseMessageInfo(
                modifiedRequestResponse
            )
            if parsedModifiedResponse.status == 200:
                self.newIssueHook(
                    url=parsedModifiedResponse.url,
                    originalMessageInfo=messageInfo,
                    modifiedMessageInfo=modifiedRequestResponse,
                    toolFlag=toolFlag,
                )
