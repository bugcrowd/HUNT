from java.awt import Color
from java.awt import Dimension
from java.awt import Insets
from java.awt import GridBagLayout
from java.awt.event import ActionListener
from javax.swing import BorderFactory
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JPanel
from close_tab import CloseTab

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

        # Create a button to close tab
        button_close = JButton("x")
        button_close.setToolTipText("Close tab")
        button_close.setOpaque(False);
        button_close.setContentAreaFilled(False);
        button_close.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        button_close.setPreferredSize(Dimension(18, 18))
        button_close.setMargin(Insets(0, 0, 0, 0))
        button_close.setForeground(Color.gray)

        panel_tab.add(label_title)
        panel_tab.add(button_close)

        bugs_tab.setTabComponentAt(index, panel_tab)

        button_close.addMouseListener(CloseTab(button_close, bugs_tab))

