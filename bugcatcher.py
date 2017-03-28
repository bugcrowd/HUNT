import json
from burp import IBurpExtender
from burp import ITab
from java.awt import Dimension
from javax import swing
from javax.swing import BoxLayout
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JScrollPane
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
        self.checklist_pane = self.checklist()
        self.tabs_pane = self.tabs()
        self.draw_panes()

        return

    def checklist(self):
        box_vertical = swing.Box.createVerticalBox()

        checklist_tree = self.create_checklist_tree()
        tree = JTree(checklist_tree)
        scroll = JScrollPane(tree)

        box_vertical.add(scroll)

        return box_vertical

    def create_checklist_tree(self):
        root = DefaultMutableTreeNode("TODO Checklist")

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

    def tabs(self):
        box_vertical2 = swing.Box.createVerticalBox()
        box_horizontal2 = swing.Box.createHorizontalBox()
        box_horizontal2.add(swing.JLabel("Tabs"))
        box_vertical2.add(box_horizontal2)
        box_horizontal2 = swing.Box.createHorizontalBox()

        self._results_textarea = swing.JTextArea()
        results_output2 = swing.JScrollPane(self._results_textarea)

        box_horizontal2.add(results_output2)
        box_vertical2.add(box_horizontal2)

        return box_vertical2

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
