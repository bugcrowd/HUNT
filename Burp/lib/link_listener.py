from javax.swing.event import HyperlinkListener

class LinkListener(HyperlinkListener):
    def hyperlinkUpdate(self, hle):
        if hle.EventType.ACTIVATED == hle.getEventType():
            desktop = Desktop.getDesktop()  # noqa: F821 Jython defines Desktop
            desktop.browse(hle.getURL().toURI())

