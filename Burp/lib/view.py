import re
from java.awt import Desktop
from java.awt import Dimension
from java.awt import FlowLayout
from java.awt import Component
from java.awt.event import MouseAdapter
from javax.swing import BorderFactory
from javax.swing import DefaultCellEditor
from javax.swing import GroupLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JEditorPane
from javax.swing import JList
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTable
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import BoxLayout
from javax.swing import SwingUtilities
from javax.swing import SwingConstants
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel
from org.python.core.util import StringUtil
from issue_listener import IssueListener
from issues import Issues
from link_listener import LinkListener
from message_controller import MessageController
from scanner_table_listener import ScannerTableListener
from scanner_table_models import ScannerTableModels
from settings_action import SettingsAction
from tsl import TSL

class View:
    def __init__(self, issues):
        self.json = issues.get_json()
        self.issues_object = issues
        self.issues = issues.get_issues()
        self.scanner_issues = issues.get_scanner_issues()
        self.scanner_panes = {}
        self.scanner_tables = {}
        self.is_scanner_panes = []

        self.set_vuln_tree()
        self.set_tree()
        self.set_scanner_table_models()
        self.set_scanner_panes()
        self.set_pane()
        self.set_settings()
        self.set_tsl()

    def get_issues_object(self):
        return self.issues_object

    def set_callbacks(self, callbacks):
        self.callbacks = callbacks

    def set_helpers(self, helpers):
        self.helpers = helpers

    def get_helpers(self):
        return self.helpers

    def get_issues(self):
        return self.issues

    def get_scanner_issues(self):
        return self.scanner_issues

    def set_is_scanner_pane(self, scanner_pane):
        self.is_scanner_panes.append(scanner_pane)

    def get_is_scanner_pane(self, scanner_pane):
        for pane in self.get_is_scanner_panes():
            if pane == scanner_pane:
                return True

        return False

    def get_is_scanner_panes(self):
        return self.is_scanner_panes

    def set_vuln_tree(self):
        self.vuln_tree = DefaultMutableTreeNode("HUNT Scanner")

        vulns = self.json["issues"]

        for vuln_name in sorted(vulns):
            vuln = DefaultMutableTreeNode(vuln_name)
            self.vuln_tree.add(vuln)

            parameters = self.json["issues"][vuln_name]["params"]

            for parameter in sorted(parameters):
                param_node = DefaultMutableTreeNode(parameter)
                vuln.add(param_node)

        self.vuln_tree.add(DefaultMutableTreeNode("Settings"))

    # Creates a JTree object from the checklist
    def set_tree(self):
        self.tree = JTree(self.vuln_tree)
        self.tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION)

    def get_tree(self):
        return self.tree

    def set_scanner_table_models(self):
        self.scanner_table_models = ScannerTableModels()
        issues = self.issues

        for issue in issues:
            issue_name = issue["name"]
            issue_param = issue["param"]

            self.scanner_table_models.create_scanner_table_model(issue_name, issue_param)

    # Creates the tabs dynamically using data from the JSON file
    def set_scanner_panes(self):
        for issue in self.issues:
            issue_name = issue["name"]
            issue_param = issue["param"]
            key = issue_name + "." + issue_param

            top_pane = self.create_request_list_pane(issue_name)
            bottom_pane = self.create_tabbed_pane()

            scanner_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_pane, bottom_pane)
            self.scanner_panes[key] = scanner_pane

    def get_scanner_panes(self):
        return self.scanner_panes

    def create_request_list_pane(self, issue_name):
        request_list_pane = JScrollPane()

        return request_list_pane

    # Creates a JTabbedPane for each vulnerability per functionality
    def create_tabbed_pane(self):
        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Advisory", JScrollPane())
        tabbed_pane.add("Request", JScrollPane())
        tabbed_pane.add("Response", JScrollPane())

        self.tabbed_pane = tabbed_pane

        return tabbed_pane

    def get_settings(self):
        return self.settings

    def set_settings(self):
        self.settings = JPanel()
        layout = GroupLayout(self.settings)
        self.settings.setLayout(layout)
        layout.setAutoCreateGaps(True)

        load_file_button = JButton("Load JSON File")
        load_file_button.setActionCommand("load")
        load_file_button.addActionListener(SettingsAction(self, load_file_button, None))
        save_file_button = JButton("Save JSON File")
        save_file_button.setActionCommand("save")
        save_file_button.addActionListener(SettingsAction(self, save_file_button, self.scanner_panes))

        horizontal_group1 = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
        horizontal_group1.addComponent(load_file_button)
        horizontal_group1.addComponent(save_file_button)

        horizontal_group = layout.createSequentialGroup()
        horizontal_group.addGroup(horizontal_group1)

        layout.setHorizontalGroup(horizontal_group)

        vertical_group1 = layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
        vertical_group1.addComponent(load_file_button)
        vertical_group2 = layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
        vertical_group2.addComponent(save_file_button)

        vertical_group = layout.createSequentialGroup()
        vertical_group.addGroup(vertical_group1)
        vertical_group.addGroup(vertical_group2)

        layout.setVerticalGroup(vertical_group)

    def set_tsl(self):
        tsl = TSL(self)
        self.tree.addTreeSelectionListener(tsl)

        return

    def set_pane(self):
        status = JTextArea()
        status.setLineWrap(True)
        status.setText("Nothing selected")
        self.status = status

        request_list_pane = JScrollPane()
        scanner_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, request_list_pane, self.tabbed_pane)
        self.pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.tree), scanner_pane)
        self.pane.setDividerLocation(310)
        self.pane.getLeftComponent().setMinimumSize(Dimension(310, 300))

    def get_pane(self):
        return self.pane

    def set_scanner_pane(self, scanner_pane, issue_name, issue_param):
        key = issue_name + "." + issue_param
        request_table_pane = scanner_pane.getTopComponent()

        if key in self.scanner_tables:
            scanner_table = self.scanner_tables[key]
        else:
            scanner_table = self.create_scanner_table(scanner_pane, issue_name, issue_param)
            self.scanner_tables[key] = scanner_table

        request_table_pane.getViewport().setView(scanner_table)
        request_table_pane.revalidate()
        request_table_pane.repaint()

    def create_scanner_table(self, scanner_pane, issue_name, issue_param):
        current_model = self.scanner_table_models.get_scanner_table_model(issue_name, issue_param)

        scanner_table = JTable(current_model)
        scanner_table.getColumnModel().getColumn(0).setMaxWidth(10)
        scanner_table.putClientProperty("terminateEditOnFocusLost", True)
        scanner_table_listener = ScannerTableListener(self, scanner_table, issue_name, issue_param)
        current_model.addTableModelListener(scanner_table_listener)
        scanner_table_list_listener = IssueListener(self, scanner_table, scanner_pane, issue_name, issue_param)
        scanner_table.getSelectionModel().addListSelectionListener(scanner_table_list_listener)

        return scanner_table

    # Takes into account if there are more than one scanner issues that share the same hostname, path, name, param, and id
    def set_tabbed_pane(self, scanner_pane, request_list, issue_hostname, issue_path, issue_name, issue_param, scanner_issue_id):
        tabbed_pane = scanner_pane.getBottomComponent()
        scanner_issues = self.get_scanner_issues()
        current_issue = self.set_current_issue(scanner_issues, issue_hostname, issue_path, issue_name, issue_param, scanner_issue_id)

        advisory_tab_pane = self.set_advisory_tab_pane(current_issue)
        tabbed_pane.setComponentAt(0, advisory_tab_pane)

        request_tab_pane = self.set_request_tab_pane(current_issue)
        tabbed_pane.setComponentAt(1, request_tab_pane)

        response_tab_pane = self.set_response_tab_pane(current_issue)
        tabbed_pane.setComponentAt(2, response_tab_pane)

    def set_current_issue(self, scanner_issues, issue_hostname, issue_path, issue_name, issue_param, scanner_issue_id):
        for scanner_issue in scanner_issues:
            is_same_hostname = scanner_issue.getHostname() == issue_hostname
            is_same_path = scanner_issue.getPath() == issue_path
            is_same_name = scanner_issue.getIssueName() == issue_name
            is_same_param = scanner_issue.getParameter() == issue_param
            is_same_id = str(scanner_issue.getRequestResponse()).split("@")[1] == scanner_issue_id
            is_same_issue = is_same_hostname and is_same_path and is_same_name and is_same_param and is_same_id

            if is_same_issue:
                return scanner_issue

    def set_advisory_tab_pane(self, scanner_issue):
        advisory_pane = JEditorPane()
        advisory_pane.setEditable(False)
        advisory_pane.setEnabled(True)
        advisory_pane.setContentType("text/html")
        link_listener = LinkListener()
        advisory_pane.addHyperlinkListener(link_listener)
        advisory = "<html><b>Location</b>: {}<br><br>{}</html>"
        advisory_pane.setText(advisory.format(scanner_issue.getUrl().encode("utf-8"), scanner_issue.getIssueDetail()))

        return JScrollPane(advisory_pane)

    def set_request_tab_pane(self, scanner_issue):
        request_response = scanner_issue.getRequestResponse()
        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, True)
        message_editor.setMessage(request_response.getRequest(), True)
        component = message_editor.getComponent()

        return component

    def set_response_tab_pane(self, scanner_issue):
        request_response = scanner_issue.getRequestResponse()
        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, True)
        message_editor.setMessage(request_response.getResponse(), False)
        component = message_editor.getComponent()

        return component

    def traverse_tree(self, tree, model, issue_name, issue_param, issue_count, total_count):
        root = model.getRoot()
        count = int(root.getChildCount())
        traverse = {}

        for i in range(count):
            node = model.getChild(root, i)
            traverse["node"] = node
            tree_issue_name = node.toString()

            is_issue_name = re.search(issue_name, tree_issue_name)

            if is_issue_name:
                child_count = node.getChildCount()

                for j in range(child_count):
                    child = node.getChildAt(j)
                    traverse["child"] = child
                    tree_param_name = child.toString()

                    is_param_name = re.search(issue_param, tree_param_name)

                    if is_param_name:
                        traverse["param_text"] = issue_param + " (" + str(issue_count) + ")"
                        break

                traverse["issue_text"] = issue_name + " (" + str(total_count) + ")"
                break

        return traverse

    def set_scanner_count(self, issue_name, issue_param, issue_count, total_count):
        tree = self.get_tree()
        model = tree.getModel()
        traverse = self.traverse_tree(tree, model, issue_name, issue_param, issue_count, total_count)
        node = traverse["node"]
        child = traverse["child"]

        child.setUserObject(traverse["param_text"])
        model.nodeChanged(child)
        model.reload(node)

        node.setUserObject(traverse["issue_text"])
        model.nodeChanged(node)
        model.reload(node)

