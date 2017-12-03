import re
from javax.swing.event import TreeSelectionListener

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.view = view
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.scanner_issues = view.get_scanner_issues()
        self.scanner_panes = view.get_scanner_panes()
        self.settings = view.get_settings()

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        if node is None:
            return

        issue_name = node.getParent().toString()
        issue_param = node.toString()

        issue_name_match = re.search("\(", issue_name)
        issue_param_match = re.search("\(", issue_param)

        is_name_match = issue_name_match is not None
        is_param_match = issue_param_match is not None

        if is_name_match:
            issue_name = issue_name.split(" (")[0]

        if is_param_match:
            issue_param = issue_param.split(" (")[0]

        is_leaf = node.isLeaf()
        is_settings = is_leaf and (issue_param == "Settings")
        is_param = is_leaf and not is_settings

        if node:
            if is_param:
                key = issue_name + "." + issue_param
                scanner_pane = self.scanner_panes[key]

                self.view.set_scanner_pane(scanner_pane, issue_name, issue_param)
                pane.setRightComponent(scanner_pane)
            elif is_settings:
                pane.setRightComponent(self.settings)
            else:
                print "No description for " + issue_name + " " + issue_param
        else:
            print "Cannot set a pane for " + issue_name + " " + issue_param


