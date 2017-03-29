import json
from burp import IBurpExtender
from burp import ITab
from javax import swing
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTree
from javax.swing import SwingConstants
from javax.swing.tree import DefaultMutableTreeNode

class BurpExtender(IBurpExtender, ITab):
    EXTENSION_NAME = "Bug Catcher"

    def registerExtenderCallbacks(self, callbacks):
        self.init()
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._callbacks.setExtensionName(self.EXTENSION_NAME)
        self._callbacks.addSuiteTab(self)

        return

    def init(self):
        self._jPanel = JPanel()
        self._jPanel.setLayout(swing.BoxLayout(self._jPanel, swing.BoxLayout.X_AXIS))

        # Create panes
        self.checklist_pane = self.create_checklist_pane()
        self.tabs_pane = self.create_tabs_pane()
        self.draw_panes()

        return

    def create_checklist_pane(self):
        checklist_tree = self.create_checklist_tree()
        tree = JTree(checklist_tree)
        scroll = JScrollPane(tree)

        return scroll

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

    def create_tabs_pane(self):
        tabbed_pane = JTabbedPane()

        description_panel = JScrollPane()
        sources_panel = JScrollPane()

        tabbed_pane.add("Description", description_panel)
        tabbed_pane.add("References", sources_panel)

        return tabbed_pane

    def draw_panes(self):
        self._jSplitPane = JSplitPane()
        self._jSplitPane.setLeftComponent(self.checklist_pane)
        self._jSplitPane.setRightComponent(self.tabs_pane)
        self._jPanel.add(self._jSplitPane)

        return

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self._jPanel
