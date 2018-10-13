from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IHttpRequestResponse
from burp import IScannerCheck
from burp import ITab
from burp import ITextEditor
from java.awt import EventQueue
from java.lang import Runnable
from javax.swing import JScrollPane
from lib.message_controller import MessageController
import re
import urlparse

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, IExtensionStateListener, IScannerCheck, ITab, ITextEditor):
    EXTENSION_NAME = "HUNT Link Finder"

    # TODO: Figure out why this gets called twice
    def __init__(self):
        self.links = []

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.view = View(callbacks)
        self.view.create_pane()
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerScannerCheck(self)

    def doPassiveScan(self, request_response):
        raw_request = request_response.getRequest()
        raw_response = request_response.getResponse()
        http_service = request_response.getHttpService()
        response = self.helpers.bytesToString(raw_response)
        request = self.helpers.analyzeRequest(http_service, raw_request)

        self.linkFinder(request, response)

        # Do not show any HUNT found issues in the Burp Link Finder window
        return []

    def linkFinder(self, request, response):
        regex = re.compile(r"[^/][`'\"]([\/][a-zA-Z0-9_.-]+)+(?!([gimuy]*[,;\s])|\/\2)")
        links = re.finditer(regex, response)

        for link in links:
            path = str(link.group(0))[2:]
            url = urlparse.urlsplit(str(request.getUrl()))
            url = url.scheme + "://" + url.hostname + path

            if url not in self.links:
                self.links.append(url)

        self.view.set_pane(self.links)

        return

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "HUNT Link Finder plugin unloaded"
        return

class View:
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def create_pane(self):
        http_service = self.callbacks.getHelpers().buildHttpService("www.bugcrowd.com", 443, False)
        request_response = self.callbacks.makeHttpRequest(http_service, "")

        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, False)
        message_editor.setMessage(request_response.getRequest(), True)
        component = message_editor.getComponent()
        pane = JScrollPane(component)
        pane.setWheelScrollingEnabled(False)

        self.pane = pane

    def set_pane(self, links):
        link_string = ""
        links.sort()

        for link in links:
            if link_string == "":
                link_string = link
            else:
                link_string = link_string + "\n" + link

        http_service = self.callbacks.getHelpers().buildHttpService("www.bugcrowd.com", 443, False)
        text = self.callbacks.getHelpers().stringToBytes(link_string)
        request_response = self.callbacks.makeHttpRequest(http_service, text)

        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, False)
        message_editor.setMessage(request_response.getRequest(), True)
        component = message_editor.getComponent()

        self.pane.setViewportView(component)

    def get_pane(self):
        return self.pane

if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
