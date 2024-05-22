from burp import IBurpExtenderCallbacks
from burp.IParameter import (
    PARAM_BODY,
    PARAM_COOKIE,
    PARAM_JSON,
    PARAM_MULTIPART_ATTR,
    PARAM_URL,
    PARAM_XML,
    PARAM_XML_ATTR,
)
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

    def createRequestFromPost(self, requestinfo, method="GET"):
        # type: (byte[], str) -> byte[]
        """
        Receives headers from a POST request, removes POST-specific ones, changes the
        method and inserts parameters
        """
        modifiedHeaders = requestinfo.headers
        modifiedRequestLine = method + modifiedHeaders[0][4:]
        modifiedHeaders[0] = modifiedRequestLine
        postOnlyHeaders = ["Content-Type", "Content-Length"]
        modifiedHeaders = [
            header
            for header in modifiedHeaders
            if not any(header.startswith(h) for h in postOnlyHeaders)
        ]

        emptyBodyRequest = self._helpers.buildHttpMessage(modifiedHeaders, "")

        for parameter in requestinfo.parameters:
            if parameter.getType() in [
                PARAM_COOKIE,
                PARAM_URL,
            ]:  # ignore GET parameters
                continue
            urlParameter = self._helpers.buildParameter(
                parameter.getName(), parameter.getValue(), PARAM_URL
            )
            emptyBodyRequest = self._helpers.addParameter(
                emptyBodyRequest, urlParameter
            )

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

        contentType = self.parser.parseContentType(requestInfo.headers)
        if not contentType:  # content type might be undefined
            return

        if contentType == "application/json":
            for char in ["{", "}", "[", "]"]:
                if (
                    requestInfo.body.count(char) > 1
                ):  # arrays/objects inside json can't be converted to GET
                    return

        if requestInfo.method == "POST":
            if contentType == "application/json":
                newRequest = self.createRequestFromPost(
                    requestInfo
                )  # createRequestFromPost doesn't support formdata
            else:
                newRequest = self._helpers.toggleRequestMethod(
                    messageInfo.getRequest()
                )  # toggleRequestMethod doesn't support json
            if not newRequest:
                return  # ensure that the request is possible
            modifiedRequestResponse = self._callbacks.makeHttpRequest(
                messageInfo.getHttpService(), newRequest
            )
            parsedModifiedResponse = self.parser.parseResponseMessageInfo(
                modifiedRequestResponse
            )
            if (
                parsedModifiedResponse.status >= 200
                and parsedModifiedResponse.status < 300
            ):
                self.newIssueHook(
                    url=parsedModifiedResponse.url,
                    originalMessageInfo=messageInfo,
                    modifiedMessageInfo=modifiedRequestResponse,
                    toolFlag=toolFlag,
                )
