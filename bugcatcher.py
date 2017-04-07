import ast
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
from javax.swing import JTree
from javax.swing.event import TreeSelectionEvent
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel

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
            data = str(data)
            data = ast.literal_eval(data)
            checklist = data.get("checklist")

        return checklist

    def create_pane(self):
        self.status = JLabel('Nothing selected')

        checklist_tree = self.create_checklist_tree()
        tree = JTree(checklist_tree)
        tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

        pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                JScrollPane(tree),
                JScrollPane(self.status))

        tree.addTreeSelectionListener(TSL(tree, pane, self.data))

        return pane

    # TODO: Make the tree creation dynamic using a JSON file
    def create_checklist_tree(self):
        root = DefaultMutableTreeNode("Functionality")

        account = DefaultMutableTreeNode("Account")
        account.add(DefaultMutableTreeNode("Cross Site Scripting"))
        account.add(DefaultMutableTreeNode("Cross Site Request Forgery"))
        account.add(DefaultMutableTreeNode("SQL Injection"))

        search = DefaultMutableTreeNode("Search")
        search.add(DefaultMutableTreeNode("Cross Site Scripting"))
        search.add(DefaultMutableTreeNode("SQL Injection"))

        root.add(account)
        root.add(search)

        return root

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.pane

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

        if node:
            if node.isLeaf():
                pane.setRightComponent(JLabel(node.toString()))
            else:
                pane.setRightComponent(JLabel(node.toString()))
        else:
            pane.setRightComponent(JLabel(node.toString() + ' else'))

    # TODO: Make the tabs dynamically using the JSON file
    def create_tabs(self):
        description_panel = JScrollPane(
            JLabel(str(self.data))
        )

        resources_panel = JScrollPane(
            JLabel(node.toString())
        )

        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Description", description_panel)
        tabbed_pane.add("Resources", resources_panel)

        return
