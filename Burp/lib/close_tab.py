from java.awt import Color
from java.awt.event import MouseListener

class CloseTab(MouseListener):
    def __init__(self, button, bugs_tab):
        self.button = button
        self.bugs_tab = bugs_tab

    def mouseClicked(self, e):
        selected = self.bugs_tab.getSelectedComponent()

        if selected is not None:
            self.bugs_tab.remove(selected)

    def mouseEntered(self, e):
        self.button.setForeground(Color.black)

    def mouseExited(self, e):
        self.button.setForeground(Color.gray)


