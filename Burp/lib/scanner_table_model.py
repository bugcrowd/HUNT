from java.lang import Boolean
from java.lang import String
from javax.swing.table import DefaultTableModel

class ScannerTableModel(DefaultTableModel):
    def getColumnClass(self, col):
        return [Boolean, String, String, String, String][col]

    def isCellEditable(self, row, col):
        return col == 0

