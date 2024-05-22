# GET Checker

GET Checker is a Burp Suite extension that parses all POST requests sent, converts its body to GET parameters and replicates the request as a GET one.
- Every POST request, from every source (proxy, repeater, intruder, extender);
- `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`.

## PoC
Check [usage/README.md](usage/README.md) for usage instructions.
- [This URL](http://i.geraldino2.com/dr?status=200&body=ok) should reply every request with a 200. Feel free to use it during tests.

## Structure
TODO

Additional documentation is available [here](docs.md).

### TODO
- Unit tests;
- Improve logging.
