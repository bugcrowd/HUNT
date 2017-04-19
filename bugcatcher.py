import json
from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
from java.awt import EventQueue
from java.awt.event import ActionListener
from java.awt.event import ItemListener
from java.lang import Runnable
from javax.swing import JCheckBox
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

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# TODO: Refactor to move functions into their own classes based on
#       functionality
class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab):
    EXTENSION_NAME = "Bug Catcher"

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
        is_proxy_history = invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY
        is_scanner_results = invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS
        is_correct_context = is_proxy_history or is_scanner_results

        if not is_correct_context:
            return

        functionality = self.checklist["functionality"]

        # Create the menu item for the Burp context menu
        bugcatcher_menu = JMenu("Send to Bug Catcher")

        # TODO: Sort the functionality by name and by vuln class
        for functionality_name in functionality:
            vulns = functionality[functionality_name]["vulns"]
            menu_vuln = JMenu(functionality_name)

            # Create a menu item and an action listener per vulnerability
            # class on each functionality
            for vuln_name in vulns:
                item_vuln = JMenuItem(vuln_name)
                menu_action_listener = MenuActionListener(self.view, functionality_name, vuln_name)
                item_vuln.addActionListener(menu_action_listener)
                menu_vuln.add(item_vuln)

            bugcatcher_menu.add(menu_vuln)

        burp_menu = []
        burp_menu.append(bugcatcher_menu)

        return burp_menu

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "Bug Catcher plugin unloaded"
        return


class MenuActionListener(ActionListener):
    def __init__(self, view, functionality_name, vuln_name):
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.key = functionality_name + "." + vuln_name
        self.tabbed_panes = view.get_tabbed_panes()

    def actionPerformed(self, e):
        bugs_tab = self.tabbed_panes[self.key].getComponentAt(1)
        tab_count = str(bugs_tab.getTabCount())
        bugs_tab.add(tab_count, JScrollPane())

# ItemListener that will write back to the issues.json file whenever something on the
# settings is checked or unchecked
class Settings(ItemListener):
    def __init__(self, issues, vuln_names, vuln_name, is_enabled):
        self.issues = issues
        self.vuln_names = vuln_names
        self.vuln_name = vuln_name
        self.is_enabled = is_enabled

    def itemStateChanged(self, e):
        is_checked = int(e.getStateChange()) == 1
        is_unchecked = int(e.getStateChange()) == 2

        if is_checked:
            self.issues["issues"][self.vuln_name]["enabled"] = True
            print self.vuln_name + " was checked"

        if is_unchecked:
            self.issues["issues"][self.vuln_name]["enabled"] = False
            print self.vuln_name + " was unchecked"

        with open("issues.json", "w") as data:
            data.write(json.dumps(self.issues, indent=2, sort_keys=True))
            data.close()

class Data():
    shared_state = {}

    def __init__(self):
        self.__dict__ = self.shared_state
        self.set_checklist()
        self.set_issues()

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

        self.set_program_brief()
        self.set_settings()
        self.set_targets()

        self.set_tsl()

    def get_checklist(self):
        return self.checklist

    def get_issues(self):
        return self.issues

    # TODO: Use Bugcrowd API to grab the Program Brief and Targets
    # Creates a DefaultMutableTreeNode using the JSON file data
    def set_checklist_tree(self):
        functionality = self.checklist["functionality"]

        self.checklist_tree = DefaultMutableTreeNode("Bug Catcher Check List")
        self.checklist_tree.add(DefaultMutableTreeNode("Settings"))
        self.checklist_tree.add(DefaultMutableTreeNode("Program Brief"))
        self.checklist_tree.add(DefaultMutableTreeNode("Targets"))

        # TODO: Sort the functionality by name and by vuln class
        for functionality_name in functionality:
            vulns = functionality[functionality_name]["vulns"]
            node = DefaultMutableTreeNode(functionality_name)

            for vuln_name in vulns:
                node.add(DefaultMutableTreeNode(vuln_name))

            self.checklist_tree.add(node)

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
        functionality = self.checklist["functionality"]
        self.tabbed_panes = {}

        for functionality_name in functionality:
            vulns = functionality[functionality_name]["vulns"]

            for vuln_name in vulns:
                key = functionality_name + "." + vuln_name
                tabbed_pane = self.set_tabbed_pane(functionality_name, vuln_name)
                self.tabbed_panes[key] = self.tabbed_pane

    def get_tabbed_panes(self):
        return self.tabbed_panes

    # Creates a JTabbedPane for each vulnerability per functionality
    def set_tabbed_pane(self, functionality_name, vuln_name):
        description_tab = self.set_description_tab(functionality_name, vuln_name)
        bugs_tab = self.set_bugs_tab()
        resources_tab = self.set_resource_tab(functionality_name, vuln_name)
        notes_tab = self.set_notes_tab()

        self.tabbed_pane = JTabbedPane()
        self.tabbed_pane.add("Description", description_tab)
        self.tabbed_pane.add("Bugs", bugs_tab)
        self.tabbed_pane.add("Resources", resources_tab)
        self.tabbed_pane.add("Notes", notes_tab)

    # Creates the description panel
    def set_description_tab(self, fn, vn):
        description_text = str(self.checklist["functionality"][fn]["vulns"][vn]["description"])
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
        resource_urls = self.checklist["functionality"][fn]["vulns"][vn]["resources"]
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

    def set_program_brief(self):
        self.program_brief = JTextArea()
        self.program_brief.setLineWrap(True)
        self.program_brief.setText("This is the program brief:")

    def get_program_brief(self):
        return self.program_brief

    def set_settings(self):
        self.settings = JPanel()

        issues = self.issues
        vuln_names = issues["issues"]

        for vuln_name in vuln_names:
            is_enabled = vuln_names[vuln_name]["enabled"]
            enabled_checkbox = JCheckBox(vuln_name, is_enabled)
            enabled_checkbox.addItemListener(Settings(issues, vuln_names, vuln_name, is_enabled))
            self.settings.add(enabled_checkbox)

    def get_settings(self):
        return self.settings

    def set_targets(self):
        self.targets = JTextArea()
        self.targets.setLineWrap(True)
        self.targets.setText("These are the targets:")

    def get_targets(self):
        return self.targets

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.checklist = view.get_checklist()
        self.issues = view.get_issues()
        self.tabbed_panes = view.get_tabbed_panes()
        self.program_brief = view.get_program_brief()
        self.settings = view.get_settings()
        self.targets = view.get_targets()

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        vuln_name = node.toString()
        functionality_name = node.getParent().toString()

        # TODO: Move Program Brief and Targets nodes creation elsewhere
        is_leaf = node.isLeaf()
        is_settings = is_leaf and (vuln_name == "Settings")
        is_brief = is_leaf and (vuln_name == "Program Brief")
        is_target = is_leaf and (vuln_name == "Targets")
        is_functionality = is_leaf and not (is_settings or is_brief or is_target)

        if node:
            if is_functionality:
                key = functionality_name + "." + vuln_name
                tabbed_pane = self.tabbed_panes[key]
                pane.setRightComponent(tabbed_pane)
            elif is_settings:
                pane.setRightComponent(self.settings)
            elif is_brief:
                pane.setRightComponent(self.program_brief)
            elif is_target:
                pane.setRightComponent(self.targets)
            else:
                print "No description for " + vuln_name
        else:
            print "Cannot set a pane for " + vuln_name


if __name__ in [ '__main__', 'main' ] :
    EventQueue.invokeLater(Run(BurpExtender))
