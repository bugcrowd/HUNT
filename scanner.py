import json
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    EXTENSION_NAME = "Bug Catcher Scanner"

    def __init__(self):
        self.issues = Issues()

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.registerScannerCheck(self)

    def doPassiveScan(self, request_response):
        current_issues = self.issues.get_scanner_issues()

        raw_request = request_response.getRequest()
        raw_response = request_response.getResponse()
        request = self.helpers.analyzeRequest(raw_request)
        response = self.helpers.analyzeResponse(raw_response)

        parameters = request.getParameters()
        vuln_parameters = self.check_parameters(parameters)

        is_not_empty = len(vuln_parameters) > 0

        if is_not_empty:
            self.create_scanner_issues(vuln_parameters, request_response)

        # Test code
        for issue in current_issues:
            print issue.getUrl()
            print issue.getParameter()
            print

        # Do not show any Bugcrowd found issues in the Scanner window
        return None

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def check_parameters(self, parameters):
        vuln_parameters = []
        issues = self.issues.get_issues()

        for parameter in parameters:
            # Make sure that the parameter is not from the cookies
            # https://portswigger.net/burp/extender/api/constant-values.html#burp.IParameter
            is_not_cookie = parameter.getType() != 2

            if is_not_cookie:
                # Handle double URL encoding just in case
                parameter_decoded = self.helpers.urlDecode(parameter.getName())
                parameter_decoded = self.helpers.urlDecode(parameter_decoded)
            else:
                continue

            # Check to see if the current parameter is a potentially vuln parameter
            for issue in issues:
                vuln_parameter = str(issue.keys()[0])
                is_vuln_found = parameter_decoded == vuln_parameter

                if is_vuln_found:
                    vuln_parameters.append(issue)

        return vuln_parameters

    def create_scanner_issues(self, vuln_parameters, request_response):
        for vuln_parameter in vuln_parameters:
            issues = self.issues.get_json()
            parameter = str(vuln_parameter.keys()[0])
            vuln_name = vuln_parameter.get(parameter)

            url = self.helpers.analyzeRequest(request_response).getUrl()
            http_service = request_response.getHttpService()
            http_messages = [self.callbacks.applyMarkers(request_response, None, None)]
            detail = issues["issues"][vuln_name]["detail"]
            severity = "Medium"

            is_not_dupe = self.check_duplicate_issue(url, parameter, vuln_name)

            if is_not_dupe:
                scanner_issue = ScannerIssue(url, parameter, http_service, http_messages, vuln_name, detail, severity)
                self.issues.set_scanner_issues(scanner_issue)

    def check_duplicate_issue(self, url, parameter, vuln_name):
        issues = self.issues.get_scanner_issues()

        for issue in issues:
            is_same_url = url == issue.getUrl()
            is_same_parameter = parameter == issue.getParameter()
            is_same_vuln_name = vuln_name == issue.getIssueName()
            is_dupe = is_same_url and is_same_parameter and is_same_vuln_name

            if is_dupe:
                return False

        return True

class Issues:
    scanner_issues = []
    shared_state = {}

    def __init__(self):
        self.__dict__ = self.shared_state
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
                issue = {}
                issue[parameter] = vuln_name
                self.issues.append(issue)

    def get_issues(self):
        return self.issues

    def set_scanner_issues(self, scanner_issue):
        self.scanner_issues.append(scanner_issue)

    def get_scanner_issues(self):
        return self.scanner_issues

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
