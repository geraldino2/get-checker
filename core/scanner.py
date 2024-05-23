from burp import IBurpExtenderCallbacks
from burp.IParameter import (
    PARAM_BODY,
    PARAM_COOKIE,
    PARAM_URL,
)
from parser import Parser
from webdriverxss import getWebdriver, verifyXss


XSS_PAYLOADS = ["<script>console.log('gdOLa9Iqwiy0pe2p')</script>", "foo", "bar"]


class Scanner:
    def __init__(self, helpers, callbacks, issueHook):
        # type: (IExtensionHelpers, IBurpExtenderCallbacks, function) -> None
        """Defines internal config"""
        self._helpers = helpers
        self._callbacks = callbacks
        self.parser = Parser(self._helpers, self._callbacks)
        self.newIssueHook = issueHook

    def updateRequestWithParam(self, request, parameter):
        # type: (byte[], IParameter) -> byte[]
        """
        Receives a request and an existing parameter, updates the parameter value
        """
        return self._helpers.updateParameter(request, parameter)

    def generateXssRequests(self, request, requestInfo):
        # type: (byte[], Tuple[str, str, str, List[IParameter], List[str], str]) -> List[byte[]]
        """
        Receives a request and a tuple with request information, inserts XSS payloads
        for each parameter and creates a modified request with the payload. Returns
        len(payloads)*len(parameters) requests (one for each payload-parameter pair)
        """
        xssRequests = list()
        for parameter in requestInfo.parameters:
            if parameter.getType() == PARAM_URL:
                for payload in XSS_PAYLOADS:
                    modifiedParam = self._helpers.buildParameter(
                        parameter.getName(), payload, parameter.getType()
                    )
                    xssRequests.append(
                        self.updateRequestWithParam(request, modifiedParam)
                    )
        return xssRequests

    def probeXss(self, originalMessageInfo, request, webdriver):
        # type: (IHttpRequestResponse, byte[], webdriver.Chrome) -> None
        """
        Sends a request with an XSS payload, using Burp and Selenium (for DOM XSS),
        waits for the response and checks if the payload is executed. If it is, creates
        an issue
        """
        requestInfo = self._helpers.analyzeRequest(
            originalMessageInfo.getHttpService(), request
        )
        url = str(requestInfo.getUrl())  # getUrl returns a java.net.URL object

        if verifyXss(webdriver, url):
            messageInfo = self._callbacks.makeHttpRequest(
                originalMessageInfo.getHttpService(), originalMessageInfo.getRequest()
            )
            modifiedMessageInfo = self._callbacks.makeHttpRequest(
                originalMessageInfo.getHttpService(), request
            )
            parsedModifiedResponse = self.parser.parseResponseMessageInfo(
                modifiedMessageInfo
            )
            self.newIssueHook(
                url=parsedModifiedResponse.url,
                originalMessageInfo=messageInfo,
                modifiedMessageInfo=modifiedMessageInfo,
                paramName="undefined",
            )

    def scanRequest(self, messageInfo):
        # type: (IHttpRequestResponse) -> None
        """
        Invoked on every request sent from the context menu. Iterates through valid
        parameters, one by one, changes their value to an XSS payload, sends a request,
        waits for script execution and creates an issue if the payload is executed
        """
        requestParsedInfo = self.parser.parseRequestMessageInfo(messageInfo)

        xssRequests = self.generateXssRequests(
            request=messageInfo.getRequest(), requestInfo=requestParsedInfo
        )
        webdriver = getWebdriver()

        for xssRequest in xssRequests:
            self.probeXss(
                originalMessageInfo=messageInfo, request=xssRequest, webdriver=webdriver
            )

        webdriver.quit()
