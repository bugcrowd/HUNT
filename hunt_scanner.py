import json
import re
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
from javax.swing import JComponent
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
from javax.swing.tree import DefaultTreeCellRenderer
from javax.swing.tree import DefaultTreeModel
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
            self.issues.create_scanner_issues(self.view, self.callbacks, self.helpers, vuln_parameters, request_response)

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
                param_node = DefaultMutableTreeNode(parameter)
                vuln.add(param_node)

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

            for parameter in parameters:
                issue = {
                    "name": str(vuln_name),
                    "param": str(parameter),
                    "count": 0
                }

                self.issues.append(issue)

    def get_issues(self):
        return self.issues

    def set_scanner_issues(self, scanner_issue):
        self.scanner_issues.append(scanner_issue)

    def get_scanner_issues(self):
        return self.scanner_issues

    def check_parameters(self, helpers, parameters):
        vuln_params = []
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
                vuln_param = issue["param"]
                is_vuln_found = parameter_decoded == vuln_param

                if is_vuln_found:
                    vuln_params.append(issue)

        return vuln_params

    def create_scanner_issues(self, view, callbacks, helpers, vuln_parameters, request_response):
        # Takes into account if there is more than one vulnerable parameter
        for vuln_parameter in vuln_parameters:
            print vuln_parameters
            issues = self.get_issues()
            json = self.get_json()

            issue_name = vuln_parameter["name"]
            issue_param = vuln_parameter["param"]

            url = helpers.analyzeRequest(request_response).getUrl()
            url = urlparse.urlsplit(str(url))
            url = url.scheme + "://" + url.hostname + url.path

            http_service = request_response.getHttpService()
            http_messages = [callbacks.applyMarkers(request_response, None, None)]
            detail = json["issues"][issue_name]["detail"]
            severity = "Medium"

            is_not_dupe = self.check_duplicate_issue(url, issue_param, issue_name)

            if is_not_dupe:
                for issue in issues:
                    is_name = issue["name"] == issue_name
                    is_param = issue["param"] == issue_param
                    is_issue = is_name and is_param

                    if is_issue:
                        issue["count"] += 1
                        issue_count = issue["count"]
                        break

                scanner_issue = ScannerIssue(url, issue_param, http_service, http_messages, issue_name, detail, severity)
                self.set_scanner_issues(scanner_issue)
                self.add_scanner_count(view, issue_name, issue_param, issue_count)

        print "length: " + str(len(self.get_scanner_issues()))

    def check_duplicate_issue(self, url, parameter, issue_name):
        issues = self.get_scanner_issues()

        for issue in issues:
            is_same_url = url == issue.getUrl()
            is_same_parameter = parameter == issue.getParameter()
            is_same_issue_name = issue_name == issue.getIssueName()
            is_dupe = is_same_url and is_same_parameter and is_same_issue_name

            if is_dupe:
                return False

        return True

    def add_scanner_count(self, view, issue_name, issue_param, issue_count):
        issues = self.get_issues()
        scanner_issues = self.get_scanner_issues()

        tree = view.get_pane().getLeftComponent().getViewport().getView()
        model = tree.getModel()
        root = model.getRoot()
        count = int(root.getChildCount())

        print "length: " + str(len(scanner_issues))

        # TODO: Refactor into one function that just takes nodes
        # Iterates through each vulnerability class leaf node in tree
        for i in range(count):
            node = model.getChild(root, i)
            tree_issue_name = node.toString()

            is_issue_name = re.search(issue_name, tree_issue_name)

            if is_issue_name:
                total_issues = 0
                child_count = node.getChildCount()

                # TODO: Refactor into one function that just takes nodes
                # Iterates through each parameter leaf node vulnerability class
                for j in range(child_count):
                    child = node.getChildAt(j)
                    tree_param_name = child.toString()

                    is_param_name = re.search(issue_param, tree_param_name)
                    print issue_param + " " + tree_param_name

                    # Change the display of each parameter leaf node based on
                    # how many issues are found
                    if is_param_name:
                        total_issues += issue_count
                        param_text = issue_param + " (" + str(issue_count) + ")"
                        print param_text

                        child.setUserObject(param_text)
                        model.nodeChanged(child)
                        model.reload(node)
                        break

                issue_text = issue_name + " (" + str(total_issues) + ")"
                print issue_text

                node.setUserObject(issue_text)
                model.nodeChanged(node)
                model.reload(node)
                break

# TODO: Fill out all the getters with proper returns
# TODO: Pass the entire request_response object instead of each individual parameter for the
#       class constructor.
class ScannerIssue(IScanIssue):
    def __init__(self, url, parameter, http_service, http_messages, issue_name, detail, severity):
        self.current_url = url
        self.http_service = http_service
        self.http_messages = http_messages
        self.detail = detail.replace("$param$", parameter)
        self.current_severity = severity
        self.issue_background = "Bugcrowd"
        self.issue_name = issue_name
        self.parameter = parameter
        self.remediation_background = ""

    def getParameter(self):
        return self.parameter

    def getUrl(self):
        return self.current_url

    def getIssueName(self):
        return self.issue_name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.current_severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return self.issue_background

    def getRemediationBackground(self):
        return self.remediation_background

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
