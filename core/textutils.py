import unicodedata


def normalizeString(text):
    # type: (str) -> str
    """Receives a raw string, normalizes unicoded chars and returns ascii"""
    text = text.encode("utf-8", "ignore").decode("utf-8")
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    return str(text)
