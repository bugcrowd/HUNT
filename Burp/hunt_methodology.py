from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import ITab
from burp import ITextEditor
from java.awt import EventQueue
from java.lang import Runnable
from javax.swing import JMenuItem
from javax.swing import JMenu
from lib.menu_action_listener import MenuActionListener
from lib.methodology_view import View

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab, ITextEditor):
    EXTENSION_NAME = "HUNT Methodology"

    def __init__(self):
        self.view = View()

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.view.set_callbacks(callbacks)
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        # Do not create a menu item unless getting a context menu from the proxy history or scanner results
        is_intruder_results = invocation.getInvocationContext() == invocation.CONTEXT_INTRUDER_ATTACK_RESULTS
        is_proxy_history = invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY
        is_scanner_results = invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS
        is_target_tree = invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE
        is_correct_context = is_proxy_history or is_scanner_results or is_target_tree or is_intruder_results

        if not is_correct_context:
            return

        request_response = invocation.getSelectedMessages()[0]

        functionality = self.view.get_checklist()["Functionality"]

        # Create the menu item for the Burp context menu
        hunt_methodology_menu = JMenu("Send to HUNT Methodology")

        for functionality_name in sorted(functionality):
            tests = functionality[functionality_name]["tests"]
            menu_test = JMenu(functionality_name)

            # Create a menu item and an action listener per vulnerability
            # class on each functionality
            for test_name in sorted(tests):
                item_test = JMenuItem(test_name)
                menu_action_listener = MenuActionListener(self.view, self.callbacks, request_response, functionality_name, test_name)
                item_test.addActionListener(menu_action_listener)
                menu_test.add(item_test)

            hunt_methodology_menu.add(menu_test)

        burp_menu = []
        burp_menu.append(hunt_methodology_menu)

        return burp_menu

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "HUNT Methodology plugin unloaded"
        return

if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
