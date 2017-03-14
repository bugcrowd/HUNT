import json
from burp import IBurpExtender
from java.io import PrintWriter

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Bug Catcher")

        stdout = PrintWriter(callbacks.getStdout(), True)

        with open('issues.json') as data_file:
            data = json.load(data_file)

            for p in data["issues"]:
                stdout.println(p)

        return

