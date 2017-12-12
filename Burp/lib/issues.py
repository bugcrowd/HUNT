import json
import re
import os
import urllib2
import urlparse
from scanner_issue import ScannerIssue

class Issues:
    scanner_issues = []
    total_count = {}
    issues_count = {}

    def __init__(self):
        self.set_json()
        self.set_issues()

    def set_json(self):
        data_file = os.getcwd() + os.sep + "conf" + os.sep + "issues.json"

        try:
            with open(data_file) as data:
                self.json = json.load(data)
        except Exception as e:
            print e

    def get_json(self):
        return self.json

    def set_issues(self):
        self.issues = []
        issues = self.json["issues"]

        for issue_name in issues:
            parameters = issues[issue_name]["params"]

            for parameter in parameters:
                issue = {
                    "name": issue_name.encode("utf-8").strip(),
                    "param": parameter.encode("utf-8").strip(),
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

        for parameter in parameters:
            # Make sure that the parameter is not from the cookies
            # https://portswigger.net/burp/extender/api/constant-values.html#burp.IParameter
            is_not_cookie = parameter.getType() != 2

            if is_not_cookie:
                # Handle double URL encoding just in case
                parameter_decoded = helpers.urlDecode(parameter.getName())
                parameter_decoded = helpers.urlDecode(parameter_decoded)

                self.check_vuln_params(vuln_params, parameter_decoded, parameter)

        return vuln_params

    def check_vuln_params(self, vuln_params, parameter_decoded, parameter):
        for issue in self.issues:
            vuln_name = issue["name"]
            vuln_param = issue["param"]
            is_vuln_found = re.search(vuln_param, parameter_decoded, re.IGNORECASE)

            if is_vuln_found:
                self.vuln_param_add(vuln_params, vuln_name, vuln_param, parameter_decoded, parameter)
                #self.vuln_param_found(vuln_params, vuln_name, vuln_param, parameter_decoded, parameter)
            else:
                continue

    def vuln_param_found(self, vuln_params, vuln_name, vuln_param, parameter_decoded, parameter):
        is_same_vuln_name = vuln_param == parameter_decoded

        if is_same_vuln_name:
            self.vuln_param_add(vuln_params, vuln_name, vuln_param, parameter_decoded, parameter)
        else:
            self.vuln_param_lookup(vuln_params, vuln_name, vuln_param, parameter_decoded, parameter)

    def vuln_param_lookup(self, vuln_params, vuln_name, vuln_param, parameter_decoded, parameter):
        # Put try catch
        url = "http://api.pearson.com/v2/dictionaries/ldoce5/entries?headword=" + parameter_decoded
        response = urllib2.urlopen(url)

        # Wait a second for response to come back
        Thread.sleep(1000)

        data = json.load(response)

        # Checks an English dictionary if parameter is a real word. If it isn't, add it.
        # Catches: id_param, param_id, paramID, etc.
        # Does not catch: idea, ideology, identify, etc.
        is_real_word = int(data["count"]) > 0

        if not is_real_word:
            self.vuln_param_add(vuln_params, vuln_name, vuln_param, parameter_decoded, parameter.getValue())

    def vuln_param_add(self, vuln_params, vuln_name, vuln_param, param, value):
        vuln_params.append({
            "vuln_name": vuln_name,
            "vuln_param": vuln_param,
            "param": param,
            "value": value
        })

    def create_scanner_issues(self, view, callbacks, helpers, vuln_parameters, request_response):
        issues = self.issues
        json = self.json

        # Takes into account if there is more than one vulnerable parameter
        for vuln_parameter in vuln_parameters:
            issue_name = vuln_parameter["vuln_name"]
            vuln_param = vuln_parameter["vuln_param"]
            param_name = vuln_parameter["param"]
            param_value = vuln_parameter["value"]

            url = helpers.analyzeRequest(request_response).getUrl()
            url = urlparse.urlsplit(str(url))
            hostname = url.hostname
            path = url.path
            url = url.scheme + "://" + url.hostname + url.path

            http_service = request_response.getHttpService()
            http_messages = [callbacks.applyMarkers(request_response, None, None)]
            detail = json["issues"][issue_name]["detail"]
            severity = "Medium"

            scanner_issue = ScannerIssue(url, issue_name, param_name, vuln_param, param_value, hostname, path, http_service, http_messages, detail, severity, request_response)
            is_scanner_issue_dupe = self.check_duplicate_issue(scanner_issue)

            if is_scanner_issue_dupe:
                continue
            else:
                self.set_scanner_issues(scanner_issue)

            issue_count = self.set_issue_count(issue_name, vuln_param)
            total_count = self.total_count[issue_name]

            view.set_scanner_count(issue_name, vuln_param, issue_count, total_count)
            view.scanner_table_models.set_scanner_table_model(scanner_issue, issue_name, param_name, vuln_param)

    def check_duplicate_issue(self, scanner_issue_local):
        scanner_issues = self.get_scanner_issues()

        for scanner_issue in scanner_issues:
            is_same_issue_name = scanner_issue_local.getIssueName() == scanner_issue.getIssueName()
            is_same_parameter = scanner_issue_local.getParameter() == scanner_issue.getParameter()
            is_same_vuln_parameter = scanner_issue_local.getVulnParameter() == scanner_issue.getVulnParameter()
            is_same_hostname = scanner_issue_local.getHostname() == scanner_issue.getHostname()
            is_same_path = scanner_issue_local.getPath() == scanner_issue.getPath()
            is_dupe = is_same_issue_name and is_same_parameter and is_same_vuln_parameter and is_same_hostname and is_same_path

            if is_dupe:
                return True

        return False

    def set_issue_count(self, issue_name, issue_param):
        for issue in self.issues:
            is_name = issue["name"] == issue_name
            is_param = issue["param"] == issue_param
            is_issue = is_name and is_param

            if is_issue:
                issue["count"] += 1
                is_total_key_exists = issue_name in self.total_count

                if is_total_key_exists:
                    self.total_count[issue_name] += 1
                else:
                    self.total_count[issue_name] = 1

                key = issue_name + "." + issue_param
                is_issue_key_exists = key in self.issues_count

                if is_issue_key_exists:
                    self.issues_count[key] += 1
                else:
                    self.issues_count[key] = 1

                return issue["count"]

    def get_issues_count(self, issue_name, issue_param):
        key = issue_name + "." + issue_param
        return self.issues_count[key]

    def change_issues_count(self, issue_name, issue_param, is_checked):
        key = issue_name + "." + issue_param

        if is_checked:
            self.issues_count[key] -= 1
        else:
            self.issues_count[key] += 1

    def get_total_count(self, issue_name):
        return self.total_count[issue_name]

    def change_total_count(self, issue_name, is_checked):
        if is_checked:
            self.total_count[issue_name] -= 1
        else:
            self.total_count[issue_name] += 1


