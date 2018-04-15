from java.awt import Desktop
from javax.swing.event import HyperlinkListener


class LinkListener(HyperlinkListener):
    def hyperlinkUpdate(self, hle):
        if hle.EventType.ACTIVATED == hle.getEventType():
            desktop = Desktop.getDesktop()
            desktop.browse(hle.getURL().toURI())
