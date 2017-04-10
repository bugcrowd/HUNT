import json
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
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

# TODO: Refactor to move functions into their own classes based on
# functionality
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    EXTENSION_NAME = "Bug Catcher"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.data = self.get_data()
        self.pane = self.create_pane()
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.addSuiteTab(self)

        return

    def createMenuItems(self, invocation):
        data = self.data
        functionality = data["functionality"]

        # Create the menu item for the Burp context menu
        bugcatcher_menu = JMenu("Send to Bug Catcher")

        # TODO: Sort the functionality by name and by vuln class
        for functionality_name in functionality:
            vulns = functionality[functionality_name]["vulns"]
            menu_vuln = JMenu(functionality_name)

            for vuln_name in vulns:
                item_vuln = JMenuItem(vuln_name)
                menu_vuln.add(vuln_name)

            bugcatcher_menu.add(menu_vuln)


        burp_menu = []
        burp_menu.append(bugcatcher_menu)

        return burp_menu

    # TODO: Move to Data class
    def get_data(self):
        with open("checklist.json") as data_file:
            data = json.load(data_file)
            checklist = data["checklist"]

        return checklist

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

        checklist_tree = self.create_checklist_tree()
        tree = JTree(checklist_tree)
        tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

        pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                JScrollPane(tree),
                JScrollPane(self.status)
        )

        tree.addTreeSelectionListener(TSL(tree, pane, self.data))

        return pane

    # TODO: Move to View class
    # TODO: Use Bugcrowd API to grab the Program Brief and Targets
    # Creates the tree dynamically using the JSON file
    def create_checklist_tree(self):
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

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.pane

# TODO: Put function for getting data here
class Data():
    def __init__(self):
        return

class TSL(TreeSelectionListener):
    def __init__(self, tree, pane, data):
        self.tree = tree
        self.pane = pane
        self.data = data

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()
        parent = node.getParent().toString()

        is_leaf = node.isLeaf()
        is_brief = is_leaf and (node.toString() == "Program Brief")
        is_target = is_leaf and (node.toString() == "Targets")
        is_functionality = is_leaf and not (is_brief or is_target)

        if node:
            if is_functionality:
                pane.setRightComponent(self.create_tabs(node, parent))
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

    # Creates the tabs dynamically using data from the JSON file
    def create_tabs(self, node, parent):
        vuln_name = node.toString()
        description_text = str(self.data["functionality"][parent]["vulns"][vuln_name]["description"])
        resource_urls = self.data["functionality"][parent]["vulns"][vuln_name]["resources"]
        resource_text = ""

        for url in resource_urls:
            resource_text = resource_text + str(url) + "\n"

        # Renders the description tab
        description_textarea = JTextArea()
        description_textarea.setLineWrap(True)
        description_textarea.setText(description_text)
        description_panel = JScrollPane(description_textarea)

        # Renders the bugs tab
        bugs_textarea = JScrollPane()
        bugs_panel = JScrollPane(bugs_textarea)

        # Renders the resources tab
        resource_textarea = JTextArea()
        resource_textarea.setLineWrap(True)
        resource_textarea.setWrapStyleWord(True)
        resource_textarea.setText(resource_text)
        resources_panel = JScrollPane(resource_textarea)

        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Description", description_panel)
        tabbed_pane.add("Bugs", bugs_panel)
        tabbed_pane.add("Resources", resources_panel)

        return tabbed_pane
