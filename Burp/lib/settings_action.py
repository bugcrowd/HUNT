import json
from java.awt.event import ActionListener
from javax.swing import JFileChooser

class SettingsAction(ActionListener):
    def __init__(self, view, file_button, scanner_panes):
        self.view = view
        self.file_button = file_button
        self.scanner_panes = scanner_panes

    def actionPerformed(self, e):
        file_chooser = JFileChooser()
        is_load_file = str(e.getActionCommand()) == "load"
        is_save_file = str(e.getActionCommand()) == "save"

        if is_load_file:
            file_chooser.setDialogTitle("Load JSON File")
            file_chooser.setDialogType(JFileChooser.OPEN_DIALOG)
            open_dialog = file_chooser.showOpenDialog(self.file_button)
            is_approve = open_dialog == JFileChooser.APPROVE_OPTION

            if is_approve:
                load_file = file_chooser.getSelectedFile()
                file_name = str(load_file)
                self.scanner_panes = self.view.get_scanner_panes()
                self.load_data(file_name)
            else:
                print "HUNT issues file load cancelled"

        if is_save_file:
            file_chooser.setDialogTitle("Save JSON File")
            file_chooser.setDialogType(JFileChooser.SAVE_DIALOG)
            save_dialog = file_chooser.showSaveDialog(self.file_button)
            is_approve = save_dialog == JFileChooser.APPROVE_OPTION

            if is_approve:
                save_file = str(file_chooser.getSelectedFile())
                self.save_data(save_file)
            else:
                print "HUNT issues file save cancelled"

    def load_data(self, file_name):
        try:
            with open(file_name) as data_file:
                data = json.load(data_file)
        except Exception as e:
            print e

        is_empty_scanner_panes = self.scanner_panes == None

        if is_empty_scanner_panes:
            print "No scanner panes to load data into"
            return

        for issue in data["hunt_issues"]:
            key = issue["issue_name"] + "." + issue["issue_param"]
            is_scanner_pane = key in self.scanner_panes

            if is_scanner_pane:
                is_table = self.scanner_panes[key].getTopComponent().getViewport().getView()

                if is_table:
                    print key
            else:
                continue

    def save_data(self, save_file):
        data = {}
        data["hunt_issues"] = []

        for key in self.scanner_panes:
            is_jtable = self.scanner_panes[key].getTopComponent().getViewport().getView()

            if is_jtable:
                rows = self.scanner_panes[key].getTopComponent().getViewport().getView().getModel().getRowCount()

                for row in range(rows):
                    table = self.scanner_panes[key].getTopComponent().getViewport().getView().getModel()
                    issue = key.split(".")

                    # Only store issues that have been checked
                    if table.getValueAt(row, 0) == False:
                        continue

                    hunt_issue = {
                        "issue_name": issue[0],
                        "issue_param": issue[1],
                        "is_checked": table.getValueAt(row, 0),
                        "vuln_param": table.getValueAt(row, 1),
                        "host": table.getValueAt(row, 2),
                        "path": table.getValueAt(row, 3)
                    }

                    data["hunt_issues"].append(hunt_issue)
        try:
            with open(save_file, 'w') as out_file:
                json.dump(data, out_file, indent=2, sort_keys=True)
        except Exception as e:
            print e

