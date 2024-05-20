class LogEntry:
    def __init__(self, tool, requestResponse, modifiedRequestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._modifiedRequestResponse = modifiedRequestResponse
        self._url = url
