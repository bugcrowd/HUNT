import json
from java.awt.event import ActionListener
from javax.swing import JFileChooser
from javax.swing import JTree
from data import Data
from methodology_tsl import TSL

class SettingsAction(ActionListener):
    def __init__(self, view, file_button, tabbed_panes):
        self.view = view
        self.file_button = file_button
        self.tabbed_panes = tabbed_panes

    def actionPerformed(self, e):
        file_chooser = JFileChooser()
        is_load_file = str(e.getActionCommand()) == "load"
        is_save_file = str(e.getActionCommand()) == "save"

        if is_load_file:
            file_chooser.setDialogTitle("Load JSON File")
            file_chooser.setDialogType(JFileChooser.OPEN_DIALOG)
            open_dialog = file_chooser.showOpenDialog(self.file_button)
            is_approve = open_dialog == JFileChooser.APPROVE_OPTION

            if is_approve:
                load_file = file_chooser.getSelectedFile()
                file_name = str(load_file)
                self.load_data(file_name)
            else:
                print("JSON file load cancelled")

        if is_save_file:
            file_chooser.setDialogTitle("Save JSON File")
            file_chooser.setDialogType(JFileChooser.SAVE_DIALOG)
            save_dialog = file_chooser.showSaveDialog(self.file_button)
            is_approve = save_dialog == JFileChooser.APPROVE_OPTION

            if is_approve:
                save_file = str(file_chooser.getSelectedFile())
                self.save_data(save_file)
            else:
                print("JSON file save cancelled")

    def load_data(self, file_name):
        self.view.set_checklist(file_name)
        checklist = self.view.get_checklist()
        self.view.set_checklist_tree()
        checklist_tree = self.view.get_checklist_tree()

        new_tree = JTree(checklist_tree)
        model = new_tree.getModel()
        old_tree = self.view.get_tree()
        old_tree.setModel(model)

        tabbed_panes = self.view.get_tabbed_panes()
        del tabbed_panes
        self.view.set_tabbed_panes()

        old_tsl = self.view.get_tsl()
        old_tree.removeTreeSelectionListener(old_tsl)
        tsl = TSL(self.view)
        old_tree.addTreeSelectionListener(tsl)

    def save_data(self, save_file):
        data = Data()
        tabbed_panes = self.tabbed_panes.iteritems()

        # Grabs all of the Notes and Bugs and saves them into the JSON file
        for key, tabbed_pane in tabbed_panes:
            bugs_tabs_count = tabbed_pane.getComponentAt(1).getTabCount()
            key = key.split(".")
            functionality_name = key[0]
            test_name = key[1]

            notes = tabbed_pane.getComponentAt(3).getText()
            data.set_notes(functionality_name, test_name, notes)

            for bug in range(bugs_tabs_count):
                request = tabbed_pane.getComponentAt(1).getComponentAt(bug).getComponentAt(0).getViewport().getView().getText().encode("utf-8")
                response = tabbed_pane.getComponentAt(1).getComponentAt(bug).getComponentAt(1).getViewport().getView().getText().encode("utf-8")

                data.set_bugs(functionality_name, test_name, request, response)

        try:
            with open(save_file, 'w') as out_file:
                json.dump(data.get_checklist(), out_file, indent=2, sort_keys=True)
        except Exception as e:
            print e


