from javax.swing.event import TableModelListener

class ScannerTableListener(TableModelListener):
    def __init__(self, view, scanner_table, issue_name, issue_param):
        self.view = view
        self.scanner_table = scanner_table
        self.issue_name = issue_name
        self.issue_param = issue_param

    def tableChanged(self, e):
        row = e.getFirstRow()
        col = e.getColumn()
        is_checked = self.scanner_table.getValueAt(row, col)
        is_changed = e.getType() == e.UPDATE

        if is_changed:
            self.view.get_issues_object().change_total_count(self.issue_name, is_checked)
            self.view.get_issues_object().change_issues_count(self.issue_name, self.issue_param, is_checked)
            issue_count = self.view.get_issues_object().get_issues_count(self.issue_name, self.issue_param)
            total_count = self.view.get_issues_object().get_total_count(self.issue_name)
            self.view.set_scanner_count(self.issue_name, self.issue_param, issue_count, total_count)

