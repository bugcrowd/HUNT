from java.lang import Object
from java.lang import Thread
from scanner_table_model import ScannerTableModel

class ScannerTableModels:
    def __init__(self):
        self.scanner_table_models = {}

    def create_scanner_table_model(self, issue_name, issue_param):
        key = issue_name + "." + issue_param
        is_model_exists = key in self.scanner_table_models

        if is_model_exists:
            return

        scanner_table_model = ScannerTableModel()
        scanner_table_model.addColumn("")
        scanner_table_model.addColumn("Parameter")
        scanner_table_model.addColumn("Host")
        scanner_table_model.addColumn("Path")
        scanner_table_model.addColumn("ID")

        self.scanner_table_models[key] = scanner_table_model

    def set_scanner_table_model(self, scanner_issue, issue_name, issue_param, vuln_param):
        key = issue_name + "." + vuln_param
        scanner_issue_id = str(scanner_issue.getRequestResponse()).split("@")[1]
        scanner_table_model = self.scanner_table_models[key]

        # Using the addRow() method requires that the data type being passed to be of type
        # Vector() or Object(). Passing a Python object of type list in addRow causes a type
        # conversion error of sorts which presents as an ArrayOutOfBoundsException. Therefore,
        # row is an instantiation of Object() to avoid this error.
        row = Object()
        row = [False, issue_param, scanner_issue.getHttpService().getHost(), scanner_issue.getPath(), scanner_issue_id]

        try:
            scanner_table_model.addRow(row)
        except Exception as e:
            print e
            #print "Error inserting row: " + key + " " + scanner_issue.getHttpService().getHost() + " " + str(scanner_issue.getPath() + " " + scanner_issue_id)

        # Wait for ScannerTableModel to update as to not get an ArrayOutOfBoundsException.
        #Thread.sleep(500)

    def get_scanner_table_model(self, issue_name, issue_param):
        key = issue_name + "." + issue_param

        return self.scanner_table_models[key]

