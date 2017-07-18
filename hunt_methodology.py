import json
from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
from java.awt import EventQueue
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt.event import ActionListener
from java.awt.event import ItemListener
from java.io import FileWriter
from java.lang import Runnable
from javax.swing import GroupLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JFileChooser
from javax.swing import JMenu
from javax.swing import JMenuBar
from javax.swing import JMenuItem
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.event import TreeSelectionEvent
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel
from org.python.core.util import StringUtil

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab):
    EXTENSION_NAME = "HUNT - Methodology"

    def __init__(self):
        data = Data()
        self.checklist = data.get_checklist()
        self.issues = data.get_issues()

        self.view = View(self.checklist, self.issues)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        # Do not create a menu item unless getting a context menu from the proxy history or scanner results
        is_intruder_results = invocation.getInvocationContext() == invocation.CONTEXT_INTRUDER_ATTACK_RESULTS
        is_proxy_history = invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY
        is_scanner_results = invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS
        is_target_tree = invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE
        is_correct_context = is_proxy_history or is_scanner_results or is_target_tree or is_intruder_results

        if not is_correct_context:
            return

        request_response = invocation.getSelectedMessages()[0]

        functionality = self.checklist["Functionality"]

        # Create the menu item for the Burp context menu
        bugcatcher_menu = JMenu("Send to HUNT - Methodology")

        # TODO: Sort the functionality by name and by vuln class
        for functionality_name in functionality:
            tests = functionality[functionality_name]["tests"]
            menu_test = JMenu(functionality_name)

            # Create a menu item and an action listener per vulnerability
            # class on each functionality
            for test_name in tests:
                item_test = JMenuItem(test_name)
                menu_action_listener = MenuActionListener(self.view, self.callbacks, request_response, functionality_name, test_name)
                item_test.addActionListener(menu_action_listener)
                menu_test.add(item_test)

            bugcatcher_menu.add(menu_test)

        burp_menu = []
        burp_menu.append(bugcatcher_menu)

        return burp_menu

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "HUNT - Methodology plugin unloaded"
        return

class MenuActionListener(ActionListener):
    def __init__(self, view, callbacks, request_response, functionality_name, vuln_name):
        self.view = view
        self.callbacks = callbacks
        self.request_response = request_response
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.key = functionality_name + "." + vuln_name
        self.tabbed_panes = view.get_tabbed_panes()

    def actionPerformed(self, e):
        bugs_tab = self.tabbed_panes[self.key].getComponentAt(1)
        tab_count = str(bugs_tab.getTabCount())

        request_tab = self.view.set_request_tab_pane(self.request_response)
        response_tab = self.view.set_response_tab_pane(self.request_response)
        bugs_tabbed_pane = self.view.set_bugs_tabbed_pane(request_tab, response_tab)

        bugs_tab.add(tab_count, bugs_tabbed_pane)
        index = bugs_tab.indexOfTab(tab_count)
        panel_tab = JPanel(GridBagLayout())
        panel_tab.setOpaque(False)
        label_title = JLabel(tab_count)
        button_close = JButton("x")
        button_close.setBorder(None)

        panel_tab.add(label_title)
        panel_tab.add(button_close)

        bugs_tab.setTabComponentAt(index, panel_tab)

        button_close.addActionListener(CloseTab(bugs_tab))

class CloseTab(ActionListener):
    def __init__(self, bugs_tab):
        self.bugs_tab = bugs_tab

    def actionPerformed(self, e):
        selected = self.bugs_tab.getSelectedComponent()

        if selected != None:
            self.bugs_tab.remove(selected)

# Singleton/Borg
class Data():
    shared_state = {}

    def __init__(self):
        self.__dict__ = self.shared_state
        self.set_checklist()
        self.set_issues()

    # Use callbacks.saveToTempFile()
    def set_checklist(self):
        with open("checklist.json") as data_file:
            data = json.load(data_file)
            self.checklist = data["checklist"]

    def get_checklist(self):
        return self.checklist

    def set_issues(self):
        with open("issues.json") as data_file:
            self.issues = json.load(data_file)

    def get_issues(self):
        return self.issues

class View:
    def __init__(self, checklist, issues):
        self.checklist = checklist
        self.issues = issues

        self.set_checklist_tree()
        self.set_tree()
        self.set_pane()
        self.set_tabbed_panes()
        self.set_settings()

        self.set_tsl()

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

        # TODO: Sort the functionality by name and by test name
        for functionality_name in functionality:
            tests = functionality[functionality_name]["tests"]
            node = DefaultMutableTreeNode(functionality_name)

            for test_name in tests:
                node.add(DefaultMutableTreeNode(test_name))

            functionality_node.add(node)

    # Creates a JTree object from the checklist
    def set_tree(self):
        self.tree = JTree(self.checklist_tree)
        self.tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

    def get_tree(self):
        return self.tree

    # TODO: Figure out how to use JCheckboxTree instead of a simple JTree
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
                    JTabbedPane()
        )

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
        tsl = TSL(self)
        self.tree.addTreeSelectionListener(tsl)

        return

    def set_settings(self):
        self.settings = JPanel()
        layout = GroupLayout(self.settings)
        self.settings.setLayout(layout)
        layout.setAutoCreateGaps(True)

        load_file_button = JButton("Load JSON File")
        load_file_button.setActionCommand("load")
        load_file_button.addActionListener(SettingsAction(load_file_button, None))
        save_file_button = JButton("Save JSON File")
        save_file_button.setActionCommand("save")
        save_file_button.addActionListener(SettingsAction(save_file_button, self.tabbed_panes))

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
        raw_request = request_response.getRequest()
        request_body = StringUtil.fromBytes(raw_request)
        request_body = request_body.encode("utf-8")

        request_tab_textarea = JTextArea(request_body)
        request_tab_textarea.setLineWrap(True)

        return JScrollPane(request_tab_textarea)

    def set_response_tab_pane(self, request_response):
        raw_response = request_response.getResponse()
        response_body = StringUtil.fromBytes(raw_response)
        response_body = response_body.encode("utf-8")

        response_tab_textarea = JTextArea(response_body)
        response_tab_textarea.setLineWrap(True)

        return JScrollPane(response_tab_textarea)

    def set_bugs_tabbed_pane(self, request_tab, response_tab):
        bugs_tabbed_pane = JTabbedPane()

        bugs_tabbed_pane.add("Request", request_tab)
        bugs_tabbed_pane.add("Response", response_tab)

        return bugs_tabbed_pane

class SettingsAction(ActionListener):
    def __init__(self, file_button, tabbed_panes):
        self.file_button = file_button
        self.tabbed_panes = tabbed_panes

    def actionPerformed(self, e):
        file_chooser = JFileChooser()
        is_load_file = str(e.getActionCommand()) == "load"
        is_save_file = str(e.getActionCommand()) == "save"

        '''
        if is_load_file:
            file_chooser.setDialogTitle("Load JSON File")
            file_chooser.setDialogType(JFileChooser.LOAD_DIALOG)
            file_chooser.showOpenDialog(self.file_button)
        '''

        if is_save_file:
            file_chooser.setDialogTitle("Save JSON File")
            file_chooser.setDialogType(JFileChooser.SAVE_DIALOG)
            save_dialog = file_chooser.showSaveDialog(self.file_button)
            is_approve = save_dialog == JFileChooser.APPROVE_OPTION

            if is_approve:
                save_file = file_chooser.getSelectedFile()
                self.save_data(save_file)
            else:
                print "save cancelled"

    def save_data(self, save_file):
        tabbed_panes = self.tabbed_panes.iteritems()

        for key, tabbed_pane in tabbed_panes:
            bugs_tabs_count = tabbed_pane.getComponentAt(1).getTabCount()

            for bug in range(bugs_tabs_count):
                key = key.split(".")
                functionality = key[0]
                test = key[1]
                request = tabbed_pane.getComponentAt(1).getComponentAt(bug).getComponentAt(1).getViewport().getView().getText().encode("utf-8")
                response = tabbed_pane.getComponentAt(1).getComponentAt(bug).getComponentAt(2).getViewport().getView().getText().encode("utf-8")


            notes = tabbed_pane.getComponentAt(2).getViewport().getView()
        '''
        file_writer = FileWriter(save_file)
        file_writer.close()
        '''

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.checklist = view.get_checklist()
        self.issues = view.get_issues()
        self.tabbed_panes = view.get_tabbed_panes()
        self.settings = view.get_settings()

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        # Check if node is root. If it is, don't display anything
        if node == None or node.getParent() == None:
            return

        test_name = node.toString()
        functionality_name = node.getParent().toString()

        is_leaf = node.isLeaf()
        is_settings = is_leaf and (test_name == "Settings")
        is_folder = is_leaf and (test_name == "Functionality")
        is_functionality = is_leaf and not is_settings

        if node:
            if is_functionality:
                key = functionality_name + "." + test_name
                tabbed_pane = self.tabbed_panes[key]
                pane.setRightComponent(tabbed_pane)
            elif is_settings:
                pane.setRightComponent(self.settings)
            else:
                print "No description for " + test_name
        else:
            print "Cannot set a pane for " + test_name


if __name__ in [ '__main__', 'main' ] :
    EventQueue.invokeLater(Run(BurpExtender))
