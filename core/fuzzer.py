from burp import IBurpExtenderCallbacks
from java.util import ArrayList
from threading import Lock
from parser import Parser

class Fuzzer:
    def __init__(self, helpers, callbacks, issueHook):
        self._helpers = helpers
        self._callbacks = callbacks
        self.parser = Parser(self._helpers, self._callbacks)
        self.newIssueHook = issueHook

    def fuzzRequestVerb(self, messageInfo, toolFlag = IBurpExtenderCallbacks.TOOL_PROXY):
        # type: (IHttpRequestResponse, int) -> None
        """
        Invoked on every intercepted HTTP request. If it is a POST request, 
        tries to request it again using GET.
        """
        requestInfo = self.parser.parseRequestMessageInfo(
            messageInfo, toolFlag
        )

        if(requestInfo.method == "POST"):
            # Modify the request to be a GET request
            # Change the first line to "GET <path> HTTP/1.1"
            new_headers = ArrayList(requestInfo.headers)
            first_line = new_headers.get(0).replace("POST", "GET")
            new_headers.set(0, first_line)

            # Remove headers that are specific to POST requests
            headers_to_remove = ["Content-Type", "Content-Length"]
            new_headers = [header for header in new_headers if not any(header.startswith(h) for h in headers_to_remove)]

            # Create a new body for the GET request (usually empty)
            new_body = ""

            # Build the new request with modified headers and empty body
            new_request = self._helpers.buildHttpMessage(new_headers, new_body)

            # Re-send the modified request
            modifiedRequestResponse = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_request)
            parsedModifiedResponse = self.parser.parseResponseMessageInfo(modifiedRequestResponse)

            if(parsedModifiedResponse.status == 200):
                self.newIssueHook(parsedModifiedResponse.url, messageInfo, modifiedRequestResponse, toolFlag)