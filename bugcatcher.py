import json
from burp import IBurpExtender
from burp import ITab
from javax import swing
from javax.swing import JCheckBox
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
class BurpExtender(IBurpExtender, ITab):
    EXTENSION_NAME = "Bug Catcher"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.data = self.get_data()
        self.pane = self.create_pane()
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)

        return

    def get_data(self):
        with open("checklist.json") as data_file:
            data = json.load(data_file)
            checklist = data["checklist"]

        return checklist

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

    # TODO: Create nodes for Program Brief and Targets
    # Creates the tree dynamically using the JSON file
    def create_checklist_tree(self):
        data = self.data
        functionality = data["functionality"]

        root = DefaultMutableTreeNode("Functionality")

        # TODO: Sort the functionality by name
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

        if node:
            if node.isLeaf():
                pane.setRightComponent(self.create_tabs(node, parent))
            else:
                name = node.toString()
                functionality_textarea = JTextArea()
                functionality_textarea.setLineWrap(True)
                functionality_textarea.setText(name)

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

        # Renders the resources tab
        resource_textarea = JTextArea()
        resource_textarea.setLineWrap(True)
        resource_textarea.setWrapStyleWord(True)
        resource_textarea.setText(resource_text)
        resources_panel = JScrollPane(resource_textarea)

        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Description", description_panel)
        tabbed_pane.add("Resources", resources_panel)

        return tabbed_pane
