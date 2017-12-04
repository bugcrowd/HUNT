from javax.swing.event import ListSelectionListener

class IssueListener(ListSelectionListener):
    def __init__(self, view, table, scanner_pane, issue_name, issue_param):
        self.view = view
        self.table = table
        self.scanner_pane = scanner_pane
        self.issue_name = issue_name
        self.issue_param = issue_param

    def valueChanged(self, e):
        row = self.table.getSelectedRow()
        issue_param = self.table.getModel().getValueAt(row, 1)
        hostname = self.table.getModel().getValueAt(row, 2)
        path = self.table.getModel().getValueAt(row, 3)
        scanner_issue_id = self.table.getModel().getValueAt(row, 4)
        self.view.set_tabbed_pane(self.scanner_pane, self.table, hostname, path, self.issue_name, issue_param, scanner_issue_id)

