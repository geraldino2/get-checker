class LogEntry:
    def __init__(self, param, requestResponse, modifiedRequestResponse, url):
        # type: (str, IHttpRequestResponse, IHttpRequestResponse, str) -> None
        """Instantiates the dataclass"""
        self._param = param
        self._requestResponse = requestResponse
        self._modifiedRequestResponse = modifiedRequestResponse
        self._url = url
