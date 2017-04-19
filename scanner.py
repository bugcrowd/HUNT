import json
from urllib import unquote
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    EXTENSION_NAME = "Bug Catcher Scanner"

    def __init__(self):
        issues = Issues()
        self.issues = issues.get_issues()

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.registerScannerCheck(self)

    def doPassiveScan(self, request_response):
        raw_request = request_response.getRequest()
        raw_response = request_response.getResponse()
        request = self.helpers.analyzeRequest(raw_request)
        response = self.helpers.analyzeResponse(raw_response)

        parameters = request.getParameters()
        vuln_parameters = self.check_parameters(parameters)

        is_not_empty = len(vuln_parameters) != 0

        if is_not_empty:
            print vuln_parameters
            self.create_scanner_issues(vuln_parameters, request_response)
        else:
            print "No vuln parameters"

        return

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def check_parameters(self, parameters):
        vuln_parameters = []

        for parameter in parameters:
            # Handles double URL encoding just in case
            parameter_decoded = unquote(unquote(parameter.getName()))

            # Check to see if the current parameter is a potentially vuln parameter
            is_vuln_found = parameter_decoded in self.issues

            if is_vuln_found:
                vuln_parameters.append(parameter_decoded)

        return set(vuln_parameters)

    def create_scanner_issues(self, vuln_parameters, request_response):
        for vuln_parameter in vuln_parameters:
            scanner_issue = ScannerIssue(self.helpers, vuln_parameter, vuln_parameters, request_response)

            is_unique = scanner_issue in self.get_scanner_issues()

            if is_unique:
                self.issue.set_scanner_issue(scanner_issue)

        return

class Issues:
    issues = set()
    scanner_issues = set()
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
        issues = self.json["issues"]

        for vuln_name in issues:
            parameters = issues[vuln_name]["params"]

            for parameter in parameters:
                self.issues.add(parameter + "." + vuln_name)

        return self.issues

    def get_issues(self):
        return self.issues

    def set_scanner_issues(self, scanner_issue):
        scanner_issues.add(scanner_issue)

        return

    def get_scanner_issues(self):
        return scanner_issues

class ScannerIssue(IScanIssue):
    def __init__(self, helpers, vuln_parameter, vuln_parameters, request_response):
        raw_request = request_response.getRequest()
        raw_response = request_response.getResponse()

        self.request = helpers.analyzeRequest(raw_request)
        self.response = helpers.analyzeRequest(raw_response)
        self.http_service = request_response.getHttpService()
        self.url = self.request.getUrl()
        self.detail = vuln_parameters[vuln_parameter]["detail"]
        self.severity = vuln_parameters[vuln_parameter]["severity"]
        self.parameter = vuln_parameter

