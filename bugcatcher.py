import json
from burp import IBurpExtender
from burp import ITab
from java.awt import Dimension
from javax import swing
from javax.swing import BoxLayout
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import SwingConstants

class BurpExtender(IBurpExtender, ITab):
    EXTENSION_NAME = "Bug Catcher"

    def registerExtenderCallbacks(self, callbacks):
        self.checklist()
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._callbacks.setExtensionName(self.EXTENSION_NAME)
        self._callbacks.addSuiteTab(self)

        return

    def checklist(self):
        self._jPanel = JPanel()
        self._jPanel.setLayout(swing.BoxLayout(self._jPanel, swing.BoxLayout.X_AXIS))

        # Create panes
        methodology_pane = self.methodology()
        subtabs_pane = self.subtabs()
        draw_panes(methodology_pane, subtabs_pane)

        return

    def methodology(self):
        box_vertical = swing.Box.createVerticalBox()
        box_horizontal = swing.Box.createHorizontalBox()
        box_horizontal.add(swing.JLabel("Checklist", SwingConstants.RIGHT))
        box_vertical.add(box_horizontal)
        box_horizontal = swing.Box.createHorizontalBox()
        self._results_textarea = swing.JTextArea()
        results_output = swing.JScrollPane(self._results_textarea)
        box_horizontal.add(results_output)
        box_vertical.add(box_horizontal)

        #self._jPanel.add(box_vertical)

        return box_vertical

    def subtabs(self):
        box_vertical2 = swing.Box.createVerticalBox()
        box_horizontal2 = swing.Box.createHorizontalBox()
        box_horizontal2.add(swing.JLabel("Tabs"))
        box_vertical2.add(box_horizontal2)
        box_horizontal2 = swing.Box.createHorizontalBox()
        self._results_textarea = swing.JTextArea()
        results_output2 = swing.JScrollPane(self._results_textarea)
        box_horizontal2.add(results_output2)
        box_vertical2.add(box_horizontal2)

        #self._jPanel.add(box_vertical2)

        return box_vertical2

    def draw_panes(methodology_pane, subtabs_pane, self):
        self._jSplitPane = JSplitPane()
        self._jSplitPane.setLeftComponent(methodology_pane)
        self._jSplitPane.setRightComponent(subtabs_pane)
        self._jPanel.add(self._jSplitPane)

        return

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self._jPanel
