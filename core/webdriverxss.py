from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


XSS_MAGIC_STR = "gdOLa9Iqwiy0pe2p"
CHROMEDRIVER_PATH = (
    "/Users/gabrielgeraldinosouza/Downloads/chromedriver-mac-arm64/chromedriver"
)


def getWebdriver():
    # type: () -> webdriver.Chrome
    """Returns a configured Chrome WebDriver instance"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    return webdriver.Chrome(options=chrome_options, executable_path=CHROMEDRIVER_PATH)


def verifyXss(webdriver, url):
    # type: (webdriver.Chrome, str, str, List[str], str) -> bool
    """Verifies if an XSS (DOM, reflected) vulnerability exists for the given request"""
    webdriver.get(url)
    logs = webdriver.get_log("browser")  # fetches and clears the browser logs

    for log in logs:
        if log["source"] == "console-api" and XSS_MAGIC_STR in "".join(
            log["message"].split(" ")[1:]
        ):
            return True
    return False
