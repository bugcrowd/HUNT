from java.awt import Dimension
from javax.swing import GroupLayout
from javax.swing import JButton
from javax.swing import JMenu
from javax.swing import JMenuItem
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel
from org.python.core.util import StringUtil
from data import Data
from message_controller import MessageController
from menu_action_listener import MenuActionListener
from methodology_settings_action import SettingsAction
from methodology_tsl import TSL

class View:
    def __init__(self):
        self.data = Data()
        self.checklist = self.data.get_checklist()
        self.issues = self.data.get_issues()

        self.set_checklist_tree()
        self.set_tree()
        self.set_pane()
        self.set_tabbed_panes()
        self.set_settings()
        self.set_tsl()

    def set_callbacks(self, callbacks):
        self.callbacks = callbacks

    def set_checklist(self, file_name):
        self.data.set_checklist(file_name)
        self.checklist = self.data.get_checklist()

    def get_checklist(self):
        return self.checklist

    def get_issues(self):
        return self.issues

    # TODO: Create the checklist dynamically for all nodes based on JSON structure
    # Creates a DefaultMutableTreeNode using the JSON file data
    def set_checklist_tree(self):
        self.checklist_tree = DefaultMutableTreeNode("HUNT - Methodology")

        for item in self.checklist:
            node = DefaultMutableTreeNode(item)
            self.checklist_tree.add(node)

            is_functionality = node.toString() == "Functionality"

            if is_functionality:
                functionality_node = node

        functionality = self.checklist["Functionality"]

        # Sorts the functionality by name and by test name
        functionality_list = []
        for functionality_name in functionality:
            functionality_list.append(functionality_name)

        for functionality_name in sorted(functionality_list):
            tests = functionality[functionality_name]["tests"]
            node = DefaultMutableTreeNode(functionality_name)

            tests_list = []
            for test_name in tests:
                tests_list.append(test_name)

            for test_name in sorted(tests_list):
                node.add(DefaultMutableTreeNode(test_name))

            functionality_node.add(node)

    def get_checklist_tree(self):
        return self.checklist_tree

    # Creates a JTree object from the checklist
    def set_tree(self):
        self.tree = JTree(self.checklist_tree)
        self.tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

    def get_tree(self):
        return self.tree

    # TODO: Change to briefcase icon for brief, P1-P5 icons for vulns,
    #       bullseye icon for Targets, etc
    # Create a JSplitPlane with a JTree to the left and JTabbedPane to right
    def set_pane(self):
        status = JTextArea()
        status.setLineWrap(True)
        status.setText("Nothing selected")
        self.status = status

        self.pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                               JScrollPane(self.tree),
                               JTabbedPane())

        self.pane.setDividerLocation(310)
        self.pane.getLeftComponent().setMinimumSize(Dimension(310, 300))

    def get_pane(self):
        return self.pane

    # Creates the tabs dynamically using data from the JSON file
    def set_tabbed_panes(self):
        functionality = self.checklist["Functionality"]
        self.tabbed_panes = {}

        for functionality_name in functionality:
            tests = functionality[functionality_name]["tests"]

            for test_name in tests:
                key = functionality_name + "." + test_name
                tabbed_pane = self.set_tabbed_pane(functionality_name, test_name)
                self.tabbed_panes[key] = self.tabbed_pane

    def get_tabbed_panes(self):
        return self.tabbed_panes

    # Creates a JTabbedPane for each vulnerability per functionality
    def set_tabbed_pane(self, functionality_name, test_name):
        description_tab = self.set_description_tab(functionality_name, test_name)
        bugs_tab = self.set_bugs_tab()
        resources_tab = self.set_resource_tab(functionality_name, test_name)
        notes_tab = self.set_notes_tab()

        self.tabbed_pane = JTabbedPane()
        self.tabbed_pane.add("Description", description_tab)
        self.tabbed_pane.add("Bugs", bugs_tab)
        self.tabbed_pane.add("Resources", resources_tab)
        self.tabbed_pane.add("Notes", notes_tab)

    # Creates the description panel
    def set_description_tab(self, fn, vn):
        description_text = str(self.checklist["Functionality"][fn]["tests"][vn]["description"])
        description_textarea = JTextArea()
        description_textarea.setLineWrap(True)
        description_textarea.setText(description_text)
        description_panel = JScrollPane(description_textarea)

        return description_panel

    # TODO: Add functionality to remove tabs
    # Creates the bugs panel
    def set_bugs_tab(self):
        bugs_tab = JTabbedPane()

        return bugs_tab

    # Creates the resources panel
    def set_resource_tab(self, fn, vn):
        resource_urls = self.checklist["Functionality"][fn]["tests"][vn]["resources"]
        resource_text = ""

        for url in resource_urls:
            resource_text = resource_text + str(url) + "\n"

        resource_textarea = JTextArea()
        resource_textarea.setLineWrap(True)
        resource_textarea.setWrapStyleWord(True)
        resource_textarea.setText(resource_text)
        resources_panel = JScrollPane(resource_textarea)

        return resources_panel

    def set_notes_tab(self):
        notes_textarea = JTextArea()

        return notes_textarea

    def set_tsl(self):
        self.tsl = TSL(self)
        self.tree.addTreeSelectionListener(self.tsl)

        return

    def get_tsl(self):
        return self.tsl

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
        save_file_button.addActionListener(SettingsAction(None, save_file_button, self.tabbed_panes))

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

    def get_settings(self):
        return self.settings

    def set_request_tab_pane(self, request_response):
        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, True)
        message_editor.setMessage(request_response.getRequest(), True)
        component = message_editor.getComponent()

        return component

    def set_response_tab_pane(self, request_response):
        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, True)
        message_editor.setMessage(request_response.getResponse(), False)
        component = message_editor.getComponent()

        return component

    def set_bugs_tabbed_pane(self, request_tab, response_tab):
        bugs_tabbed_pane = JTabbedPane()

        bugs_tabbed_pane.add("Request", request_tab)
        bugs_tabbed_pane.add("Response", response_tab)

        return bugs_tabbed_pane



