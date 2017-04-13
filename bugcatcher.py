import json
from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
from java.awt import EventQueue
from java.awt.event import ActionEvent
from java.awt.event import ActionListener
from java.lang import Runnable
from javax import swing
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
# functionality
class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab):
    EXTENSION_NAME = "Bug Catcher"

    def __init__(self):
        self.data = self.get_data()
        self.checklist = self.create_checklist()
        self.tree = self.create_tree()
        self.pane = self.create_pane()
        self.tabbed_panes = self.create_tabbed_panes()
        self.create_tsl()

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, invocation):
        # Do not create a menu item unless getting a context menu from the proxy history
        is_proxy_history = invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY

        if not is_proxy_history:
            return

        functionality = self.data["functionality"]

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
                item_vuln.addActionListener(MenuItem(self.tree, self.pane, functionality_name, vuln_name, self.tabbed_panes))
                menu_vuln.add(item_vuln)

            bugcatcher_menu.add(menu_vuln)

        burp_menu = []
        burp_menu.append(bugcatcher_menu)

        return burp_menu

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.pane

    def extensionUnloaded(self):
        print "Bug Catcher plugin unloaded"
        return

    # TODO: Move to Data class
    def get_data(self):
        with open("checklist.json") as data_file:
            data = json.load(data_file)
            checklist = data["checklist"]

        return checklist

    # TODO: Maintain state persistence
    # TODO: Move to View class
    # TODO: Use Bugcrowd API to grab the Program Brief and Targets
    # Creates a DefaultMutableTreeNode using the JSON file data
    def create_checklist(self):
        data = self.data
        functionality = data["functionality"]

        root = DefaultMutableTreeNode("Bug Catcher Check List")
        root.add(DefaultMutableTreeNode("Program Brief"))
        root.add(DefaultMutableTreeNode("Targets"))

        # TODO: Sort the functionality by name and by vuln class
        for functionality_name in functionality:
            vulns = functionality[functionality_name]["vulns"]
            node = DefaultMutableTreeNode(functionality_name)

            for vuln_name in vulns:
                node.add(DefaultMutableTreeNode(vuln_name))

            root.add(node)

        return root

    # Creates a JTree object from the checklist
    def create_tree(self):
        tree = JTree(self.checklist)
        tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

        return tree

    # TODO: Move to View class
    # TODO: Figure out how to use JCheckboxTree instead of a simple JTree
    # TODO: Change icons to Bugcrowd logo for brief, VRT logo for vulns,
    #       bullseye for Targets, etc
    # Creates a tree event listener to dynamically render each vuln class
    # as its own pane
    def create_pane(self):
        status = JTextArea()
        status.setLineWrap(True)
        status.setText("Nothing selected")
        self.status = status

        pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                JScrollPane(self.tree),
                JTabbedPane()
        )

        return pane

    def create_tsl(self):
        tsl = TSL(self.tree, self.pane, self.data, self.tabbed_panes)
        self.tree.addTreeSelectionListener(tsl)

        return

    # Creates the tabs dynamically using data from the JSON file
    def create_tabbed_panes(self):
        functionality = self.data["functionality"]
        tabbed_panes = {}

        for functionality_name in functionality:
            vulns = functionality[functionality_name]["vulns"]

            for vuln_name in vulns:
                key = functionality_name + "." + vuln_name
                tabbed_pane = self.create_tabbed_pane(functionality_name, vuln_name)
                tabbed_panes[key] = tabbed_pane

        return tabbed_panes

    # Creates a JTabbedPane for each vulnerability per functionality
    def create_tabbed_pane(self, functionality_name, vuln_name):
        description_tab = self.create_description_tab(functionality_name, vuln_name)
        bugs_tab = self.create_bugs_tab()
        resources_tab = self.create_resource_tab(functionality_name, vuln_name)

        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Description", description_tab)
        tabbed_pane.add("Bugs", bugs_tab)
        tabbed_pane.add("Resources", resources_tab)

        return tabbed_pane

    # Creates the description panel
    def create_description_tab(self, fn, vn):
        description_text = str(self.data["functionality"][fn]["vulns"][vn]["description"])
        description_textarea = JTextArea()
        description_textarea.setLineWrap(True)
        description_textarea.setText(description_text)
        description_panel = JScrollPane(description_textarea)

        return description_panel

    # Creates the bugs panel
    def create_bugs_tab(self):
        bugs_tab = JTabbedPane()

        return bugs_tab

    # Creates the resources panel
    def create_resource_tab(self, fn, vn):
        resource_urls = self.data["functionality"][fn]["vulns"][vn]["resources"]
        resource_text = ""

        for url in resource_urls:
            resource_text = resource_text + str(url) + "\n"

        resource_textarea = JTextArea()
        resource_textarea.setLineWrap(True)
        resource_textarea.setWrapStyleWord(True)
        resource_textarea.setText(resource_text)
        resources_panel = JScrollPane(resource_textarea)

        return resources_panel

class MenuItem(ActionListener):
    def __init__(self, tree, pane, functionality_name, vuln_name, tabbed_panes):
        self.tree = tree
        self.pane = pane
        self.key = functionality_name + "." + vuln_name
        self.tabbed_panes = tabbed_panes

    def actionPerformed(self, e):
        bugs_tab = self.tabbed_panes[self.key].getComponentAt(1)
        tab_count = str(bugs_tab.getTabCount())
        bugs_tab.add(tab_count, JScrollPane())


# TODO: Put function for getting data here
class Data():
    def __init__(self):
        return

# TODO: Put all functions pertaining to creating the Burp views
class View():
    def __init__(self):
        return

class TSL(TreeSelectionListener):
    def __init__(self, tree, pane, data, tabbed_panes):
        self.tree = tree
        self.pane = pane
        self.data = data
        self.tabbed_panes = tabbed_panes

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        vuln_name = node.toString()
        functionality_name = node.getParent().toString()

        is_leaf = node.isLeaf()
        is_brief = is_leaf and (vuln_name == "Program Brief")
        is_target = is_leaf and (vuln_name == "Targets")
        is_functionality = is_leaf and not (is_brief or is_target)

        if node:
            if is_functionality:
                key = functionality_name + "." + vuln_name
                tabbed_pane = self.tabbed_panes[key]
                pane.setRightComponent(tabbed_pane)
            elif is_brief:
                brief_textarea = JTextArea()
                brief_textarea.setLineWrap(True)
                brief_textarea.setText("This is the program brief:")

                pane.setRightComponent(brief_textarea)
            elif is_target:
                target_textarea = JTextArea()
                target_textarea.setLineWrap(True)
                target_textarea.setText("These are the targets:")

                pane.setRightComponent(target_textarea)
            else:
                name = node.toString()
                functionality_textarea = JTextArea()
                functionality_textarea.setLineWrap(True)
                functionality_textarea.setText("Make a description for: " + name)

                pane.setRightComponent(functionality_textarea)
        else:
            pane.setRightComponent(JLabel('I AM ERROR'))


if __name__ in [ '__main__', 'main' ] :
    EventQueue.invokeLater(Run(BurpExtender))
