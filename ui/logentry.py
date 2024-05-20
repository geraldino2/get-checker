class LogEntry:
    def __init__(self, tool, requestResponse, modifiedRequestResponse, url):
        # type: (int, IHttpRequestResponse, IHttpRequestResponse, str) -> None
        """Instantiates the dataclass"""
        self._tool = tool
        self._requestResponse = requestResponse
        self._modifiedRequestResponse = modifiedRequestResponse
        self._url = url
