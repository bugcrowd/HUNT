import json
import os

class Data():
    shared_state = {}

    def __init__(self):
        self.__dict__ = self.shared_state
        self.set_checklist(None)
        self.set_issues()

    def set_checklist(self, file_name):
        is_empty = file_name is None

        if is_empty:
            file_name = os.getcwd() + os.sep + "conf" + os.sep + "checklist.json"

        try:
            with open(file_name) as data_file:
                data = json.load(data_file)
                self.checklist = data["checklist"]
        except Exception as e:
            print e

    def get_checklist(self):
        return self.checklist

    def set_issues(self):
        file_name = os.getcwd() + os.sep + "conf" + os.sep + "issues.json"

        try:
            with open(file_name) as data_file:
                self.issues = json.load(data_file)
        except Exception as e:
            print e

    def get_issues(self):
        return self.issues

    def set_bugs(self, functionality_name, test_name, request, response):
        bug = {
            "request": request,
            "response": response
        }

        self.checklist["Functionality"][functionality_name]["tests"][test_name]["bugs"].append(bug)

    def set_notes(self, functionality_name, test_name, notes):
        self.checklist["Functionality"][functionality_name]["tests"][test_name]["notes"] = notes


