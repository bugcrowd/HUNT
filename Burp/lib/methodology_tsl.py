from javax.swing.event import TreeSelectionListener

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.checklist = view.get_checklist()
        self.issues = view.get_issues()
        self.tabbed_panes = view.get_tabbed_panes()
        self.settings = view.get_settings()

    def valueChanged(self, tse):
        pane = self.pane
        pane.setDividerLocation(300)
        node = self.tree.getLastSelectedPathComponent()

        # Check if node is root. If it is, don't display anything
        if node is None or node.getParent() is None:
            return

        test_name = node.toString()
        functionality_name = node.getParent().toString()

        is_leaf = node.isLeaf()
        is_settings = is_leaf and (test_name == "Settings")
        is_folder = is_leaf and (test_name == "Functionality")
        is_functionality = is_leaf and not is_settings

        if node:
            if is_functionality:
                key = functionality_name + "." + test_name
                tabbed_pane = self.tabbed_panes[key]
                pane.setRightComponent(tabbed_pane)
            elif is_settings:
                pane.setRightComponent(self.settings)
            else:
                print("No description for " + test_name)
        else:
            print("Cannot set a pane for " + test_name)


