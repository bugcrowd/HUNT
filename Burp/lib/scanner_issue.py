from burp import IScanIssue

class ScannerIssue(IScanIssue):
    def __init__(self, url, issue_name, parameter, vuln_param, param_value, hostname, path, http_service, http_messages, detail, severity, request_response):
        self._url = url
        self._http_service = http_service
        self._http_messages = http_messages
        detail = detail.encode("utf-8")
        self._detail = detail.replace("$param$", parameter.encode("utf-8"))
        self._current_severity = severity
        self._request_response = request_response
        self._issue_background = ""
        self._issue_name = issue_name
        self._parameter = parameter
        self._vuln_param = vuln_param
        self._hostname = hostname
        self._path = path
        self._param_value = param_value
        self._remediation_background = ""

    def getRequestResponse(self):
        return self._request_response

    def getVulnParameter(self):
        return self._vuln_param

    def getParameter(self):
        return self._parameter

    def getParameterValue(self):
        return self._param_value

    def getHostname(self):
        return self._hostname

    def getPath(self):
        return self._path

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._issue_name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._current_severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return self._issue_background

    def getRemediationBackground(self):
        return self._remediation_background

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

