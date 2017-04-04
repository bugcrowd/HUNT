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
from javax.swing import SwingConstants
from javax.swing.event import TreeSelectionEvent
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel
from java.io import PrintWriter

class BurpExtender(IBurpExtender, ITab):
    EXTENSION_NAME = "Bug Catcher"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.pane = self.create_pane()
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)

        return

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

        tree.addTreeSelectionListener(TSL(tree, pane))

        return pane

    def create_checklist_tree(self):
        root = DefaultMutableTreeNode("Bug Catcher Checklist")

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

class TSL(TreeSelectionListener):
    def __init__(self, tree, pane):
        self.tree = tree
        self.pane = pane

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        description_panel = JScrollPane(
            JLabel(node.toString())
        )

        resources_panel = JScrollPane(
            JLabel(node.toString())
        )

        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Description", description_panel)
        tabbed_pane.add("Resources", resources_panel)

        if node:
            if node.isLeaf():
                pane.setRightComponent(tabbed_pane)
            else:
                pane.setRightComponent(tabbed_pane)
        else:
            pane.setRightComponent(tabbed_pane)

