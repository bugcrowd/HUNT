import json
import urlparse
from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import IScanIssue
from burp import IScannerCheck
from burp import ITab
from java.awt import EventQueue
from java.awt.event import ActionListener
from java.awt.event import ItemListener
from java.lang import Runnable
from javax.swing import JCheckBox
from javax.swing import JMenu
from javax.swing import JMenuBar
from javax.swing import JMenuItem
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.event import TreeSelectionEvent
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory, IScannerCheck, ITab):
    EXTENSION_NAME = "HUNT - Scanner"

    def __init__(self):
        self.issues = Issues()
        self.view = View(self.issues.get_json())

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerScannerCheck(self)

    def doPassiveScan(self, request_response):
        raw_request = request_response.getRequest()
        raw_response = request_response.getResponse()
        request = self.helpers.analyzeRequest(raw_request)
        response = self.helpers.analyzeResponse(raw_response)

        parameters = request.getParameters()
        url = self.helpers.analyzeRequest(request_response).getUrl()
        vuln_parameters = self.issues.check_parameters(self.helpers, parameters)

        is_not_empty = len(vuln_parameters) > 0

        if is_not_empty:
            self.issues.create_scanner_issues(self.callbacks, self.helpers, vuln_parameters, request_response)
            #self.issues.set_scanner_count(self.view)

        # Do not show any Bugcrowd found issues in the Scanner window
        return []

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "HUNT - Scanner plugin unloaded"
        return

class View:
    def __init__(self, issues):
        self.issues = issues

        self.set_vuln_tree()
        self.set_tree()
        self.set_tabbed_pane()
        self.set_pane()

    def set_vuln_tree(self):
        self.vuln_tree = DefaultMutableTreeNode("Vulnerability Classes")

        vulns = self.issues["issues"]

        # TODO: Sort the functionality by name and by vuln class
        for vuln_name in vulns:
            vuln = DefaultMutableTreeNode(vuln_name)
            self.vuln_tree.add(vuln)

            parameters = self.issues["issues"][vuln_name]["params"]

            for parameter in parameters:
                vuln.add(DefaultMutableTreeNode(parameter))

    # Creates a JTree object from the checklist
    def set_tree(self):
        self.tree = JTree(self.vuln_tree)
        self.tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

    def get_tree(self):
        return self.tree

    # Creates a JTabbedPane for each vulnerability per functionality
    def set_tabbed_pane(self):
        request_tab = self.set_request_tab()
        response_tab = self.set_response_tab()

        self.tabbed_pane = JTabbedPane()
        self.tabbed_pane.add("Request", request_tab)
        self.tabbed_pane.add("Response", response_tab)

    def get_tabbed_pane(self):
        return self.tabbed_pane

    def set_request_tab(self):
        request_tab = JScrollPane()

        return request_tab

    def set_response_tab(self):
        response_tab = JScrollPane()

        return response_tab

    def set_pane(self):
        status = JTextArea()
        status.setLineWrap(True)
        status.setText("Nothing selected")
        self.status = status

        scanner_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                       JScrollPane(),
                       self.tabbed_pane
        )

        self.pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    JScrollPane(self.tree),
                    scanner_pane
        )

    def get_pane(self):
        return self.pane

class IssueTSL(TreeSelectionListener):
    def __init__(self, view):
        return

    def valueChanged(self, tse):
        return

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.issues = view.get_issues()
        self.tree = view.get_tree()
        self.pane = view.get_pane()

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        vuln_name = node.toString()
        functionality_name = node.getParent().toString()

        is_leaf = node.isLeaf()

        if node:
            if is_leaf:
                print "Yes??"
            else:
                print "No description for " + vuln_name
        else:
            print "Cannot set a pane for " + vuln_name

class Issues:
    scanner_issues = []

    def __init__(self):
        self.set_json()
        self.set_issues()

    def set_json(self):
        with open("issues.json") as data_file:
            self.json = json.load(data_file)

    def get_json(self):
        return self.json

    def set_issues(self):
        self.issues = []
        issues = self.json["issues"]

        for vuln_name in issues:
            parameters = issues[vuln_name]["params"]

            # TODO: Refactor and change from dict to list because de-duping is handled elsewhere
            for parameter in parameters:
                issue = {}
                issue[parameter] = vuln_name
                self.issues.append(issue)

    def get_issues(self):
        return self.issues

    def set_scanner_issues(self, scanner_issue):
        self.scanner_issues.append(scanner_issue)

    def get_scanner_issues(self):
        return self.scanner_issues

    def check_parameters(self, helpers, parameters):
        vuln_parameters = []
        issues = self.get_issues()

        for parameter in parameters:
            # Make sure that the parameter is not from the cookies
            # https://portswigger.net/burp/extender/api/constant-values.html#burp.IParameter
            is_not_cookie = parameter.getType() != 2

            if is_not_cookie:
                # Handle double URL encoding just in case
                parameter_decoded = helpers.urlDecode(parameter.getName())
                parameter_decoded = helpers.urlDecode(parameter_decoded)
            else:
                continue

            # TODO: Use regex at the beginning and end of the string for params like "id".
            #       Example: id_param, param_id, paramID, etc
            # Check to see if the current parameter is a potentially vuln parameter
            for issue in issues:
                vuln_parameter = str(issue.keys()[0])
                is_vuln_found = parameter_decoded == vuln_parameter

                if is_vuln_found:
                    vuln_parameters.append(issue)

        return vuln_parameters

    def create_scanner_issues(self, callbacks, helpers, vuln_parameters, request_response):
        # Takes into account if there is more than one vulnerable parameter
        for vuln_parameter in vuln_parameters:
            issues = self.get_json()
            parameter = str(vuln_parameter.keys()[0])
            vuln_name = vuln_parameter.get(parameter)

            url = helpers.analyzeRequest(request_response).getUrl()
            url = urlparse.urlsplit(str(url))
            url = url.scheme + "://" + url.hostname + url.path

            http_service = request_response.getHttpService()
            http_messages = [callbacks.applyMarkers(request_response, None, None)]
            detail = issues["issues"][vuln_name]["detail"]
            severity = "Medium"

            is_not_dupe = self.check_duplicate_issue(url, parameter, vuln_name)

            if is_not_dupe:
                scanner_issue = ScannerIssue(url, parameter, http_service, http_messages, vuln_name, detail, severity)
                self.set_scanner_issues(scanner_issue)

    def set_scanner_count(self, view):
        issues = self.get_scanner_issues()

        for issue in issues:
            issue_name = issue.getIssueName()

            print issue_name

        return

    def check_duplicate_issue(self, url, parameter, vuln_name):
        issues = self.get_scanner_issues()

        for issue in issues:
            is_same_url = url == issue.getUrl()
            is_same_parameter = parameter == issue.getParameter()
            is_same_vuln_name = vuln_name == issue.getIssueName()
            is_dupe = is_same_url and is_same_parameter and is_same_vuln_name

            if is_dupe:
                return False

        return True


# TODO: Fill out all the getters with proper returns
# TODO: Pass the entire request_response object instead of each individual parameter for the
#       class constructor.
class ScannerIssue(IScanIssue):
    def __init__(self, url, parameter, http_service, http_messages, vuln_name, detail, severity):
        self.this_url = url
        self.http_service = http_service
        self.http_messages = http_messages
        self.detail = detail.replace("$param$", parameter)
        self.this_severity = severity
        self.issue_background = "Bugcrowd"
        self.vuln_name = vuln_name
        self.parameter = parameter

    def getParameter(self):
        return self.parameter

    def getUrl(self):
        return self.this_url

    def getIssueName(self):
        return self.vuln_name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.this_severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return self.issue_background

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self.detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.http_messages

    def getHttpService(self):
        return self.http_service

if __name__ in [ '__main__', 'main' ] :
    EventQueue.invokeLater(Run(BurpExtender))
