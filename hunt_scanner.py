import json
from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
from java.awt import EventQueue
from java.awt.event import ActionListener
from java.awt.event import ItemListener
from java.lang import Runnable
from javax.swing import JCheckBox
from javax.swing import JMenu
from javax.swing import JMenuBar
from javax.swing import JMenuItem
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.event import TreeSelectionEvent
from javax.swing.event import TreeSelectionListener
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab):
    EXTENSION_NAME = "HUNT - Scanner"

    def __init__(self):
        self.data = Data()
        self.issues = self.data.get_issues()
        self.view = View(self.issues)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "HUNT - Scanner plugin unloaded"
        return

class Data:
    shared_state = {}

    def __init__(self):
        self.__dict__ = self.shared_state
        self.set_issues()

    def set_issues(self):
        with open("issues.json") as data_file:
            self.issues = json.load(data_file)

    def get_issues(self):
        return self.issues

class View:
    def __init__(self, issues):
        self.issues = issues

        self.set_vuln_tree()
        self.set_tree()
        self.set_pane()

    def set_vuln_tree(self):
        self.vuln_tree = DefaultMutableTreeNode("Vulnerability Classes")

        vulns = self.issues["issues"]

        # TODO: Sort the functionality by name and by vuln class
        for vuln_name in vulns:
            vuln = DefaultMutableTreeNode(vuln_name)
            self.vuln_tree.add(vuln)

            parameters = self.issues["issues"][vuln_name]["params"]

            for parameter in parameters:
                vuln.add(DefaultMutableTreeNode(parameter))

    # Creates a JTree object from the checklist
    def set_tree(self):
        self.tree = JTree(self.vuln_tree)
        self.tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

    def get_tree(self):
        return self.tree

    # Creates a JTabbedPane for each vulnerability per functionality
    def set_tabbed_pane(self, functionality_name, vuln_name):
        description_tab = self.set_description_tab(functionality_name, vuln_name)
        bugs_tab = self.set_bugs_tab()
        resources_tab = self.set_resource_tab(functionality_name, vuln_name)
        notes_tab = self.set_notes_tab()

        self.tabbed_pane = JTabbedPane()
        self.tabbed_pane.add("Description", description_tab)
        self.tabbed_pane.add("Bugs", bugs_tab)
        self.tabbed_pane.add("Resources", resources_tab)
        self.tabbed_pane.add("Notes", notes_tab)

    def set_pane(self):
        status = JTextArea()
        status.setLineWrap(True)
        status.setText("Nothing selected")
        self.status = status

        scanner_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                       JScrollPane(),
                       JTabbedPane()
        )

        self.pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    JScrollPane(self.tree),
                    scanner_pane
        )

    def get_pane(self):
        return self.pane

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.issues = view.get_issues()
        self.tree = view.get_tree()
        self.pane = view.get_pane()

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        vuln_name = node.toString()
        functionality_name = node.getParent().toString()

        is_leaf = node.isLeaf()

        if node:
            if is_leaf:
                print "Yes??"
            else:
                print "No description for " + vuln_name
        else:
            print "Cannot set a pane for " + vuln_name

if __name__ in [ '__main__', 'main' ] :
    EventQueue.invokeLater(Run(BurpExtender))
