# GET Checker

GET Checker is a Burp Suite extension that parses all POST requests sent, converts its body to GET parameters and replicates the request as a GET one.
- Every POST request, from every source (proxy, repeater, intruder, extender);
- `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`.

## PoC
Check [usage/README.md](usage/README.md) for usage instructions.

[This URL](http://i.geraldino2.com/dr?status=200&body=ok) should reply every request with a 200. Feel free to use it during tests.

## Structure
The defined code structure is pretty simple. `main.py` implements `BurpExtender`, deals with all that is needed to setup the extension, sets up the UI and creates a Fuzzer.

The UI is defined in ui, managing the table and log entries. `fuzzer.py` defines `Fuzzer`, who is responsible to parse requests using auxiliary modules (`parser.py`, `textutils.py`). POST requests are then converted to GET, using the `Parser` and Burp's `IExtensionHelpers`, and sent again. In case of success, a new `LogEntry` is placed into the table.

![image](codestructure.png)


Additional documentation is available [here](docs.md).

### TODO
- Unit tests;
- Improve logging.
