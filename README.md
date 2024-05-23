# XSS Detector

XSS Detector is a Burp Suite extension that parses all requests, inserts an XSS payload into
- Every POST request, from every source (proxy, repeater, intruder, extender);
- `PARAM_URL`, `PARAM_BODY` and `PARAM_COOKIE`

## PoC
Check [usage/README.md](usage/README.md) for usage instructions.

[This URL](http://i.geraldino2.com/dr?status=200&body=ok) should reply every request with a 200. Feel free to use it during tests.

## Installation
Change the path to your `chromedriver` in `CHROMEDRIVER_PATH:core/webdriverxss.py`. `chromedriver` can be downloaded [here](https://googlechromelabs.github.io/chrome-for-testing/#stable).

Then, install pip dependencies:
```
$ java -jar $JYTHON_JAR_PATH -m ensurepip # install pip
$ java -jar $JYTHON_JAR_PATH -m pip install selenium # install selenium
```

## Structure
TODO

![image](codestructure.png)


Additional documentation is available [here](docs.md).

### TODO
- Support headers and POST requests (migration from Selenium might be required);
- Support Blind XSS;
- Support more payloads (beyond `XSS_MAGIC_STR` and `console.log`);
- Improve logging.
