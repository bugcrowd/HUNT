package burp

import java.awt.FlowLayout
import javax.swing.*

class HuntOptions(
    private val huntPanel: HuntPanel,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    private val searchBar = JTextField("", 20)
    private val searchPanel = JPanel(FlowLayout(FlowLayout.LEFT))
    private val typeComboBox = JComboBox(arrayOf<String>())

    init {
        val clearButton = JButton("Clear Hunt Issues")
        val searchLabel = JLabel("Search Hunt Issues:")
        val searchButton = JButton("Search")
        val resetButton = JButton("Reset")
        typeComboBox.selectedIndex = -1
        typeComboBox.prototypeDisplayValue = "Select type"
        typeComboBox.addItem("Select type")
        clearButton.addActionListener { clearHuntIssues() }
        searchBar.addActionListener { searchHuntIssues() }
        searchButton.addActionListener { searchHuntIssues() }
        resetButton.addActionListener { resetSearch() }
        searchPanel.add(searchLabel)
        searchPanel.add(searchBar)
        searchPanel.add(typeComboBox)
        searchPanel.add(searchButton)
        searchPanel.add(resetButton)
        loadPanel.add(clearButton)
        panel.leftComponent = searchPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }


    fun searchHuntIssues() {
        val selectedType = typeComboBox.selectedItem
        SwingUtilities.invokeLater {
            val searchText = searchBar.text.toLowerCase()
            var filteredHuntIssues = this.huntPanel.huntIssues
            filteredHuntIssues = filterTypes(filteredHuntIssues)
            if (searchText.isNotEmpty()) {
                filteredHuntIssues = filteredHuntIssues
                    .filter {
                        it.comments.toLowerCase().contains(searchText) ||
                                it.url.toString().toLowerCase().contains(searchText) ||
                                callbacks.helpers.bytesToString(it.requestResponse.request).toLowerCase().contains(
                                    searchText
                                ) ||
                                callbacks.helpers.bytesToString(
                                    it.requestResponse.response ?: ByteArray(0)
                                ).toLowerCase().contains(
                                    searchText
                                )
                    }.toMutableList()
            }
            huntPanel.model.refreshHunt(filteredHuntIssues)
            if (selectedType != "Select type") {
                typeComboBox.selectedItem = selectedType
            }
            rowSelection()
        }
    }

    private fun filterTypes(huntIssues: MutableList<HuntIssue>): MutableList<HuntIssue> {
        return if (typeComboBox.selectedItem != "Select type" || typeComboBox.selectedItem == null) {
            val type = typeComboBox.selectedItem
            huntIssues
                .filter {
                    it.type == type
                }.toMutableList()
        } else {
            huntIssues
        }
    }

    private fun resetSearch() {
        searchBar.text = ""
        huntPanel.model.refreshHunt()
        rowSelection()
        updateTypes()
    }

    private fun clearHuntIssues() {
        huntPanel.model.clearHunt()
        huntPanel.requestViewer?.setMessage(ByteArray(0), true)
        huntPanel.responseViewer?.setMessage(ByteArray(0), false)
    }

    private fun rowSelection() {
        val rowCount = huntPanel.table.rowCount
        if (rowCount != -1) {
            huntPanel.table.setRowSelectionInterval(rowCount - 1, rowCount - 1)
        } else {
            huntPanel.requestViewer?.setMessage(ByteArray(0), true)
            huntPanel.responseViewer?.setMessage(ByteArray(0), false)
        }
    }

    fun updateTypes() {
        typeComboBox.removeAllItems()
        typeComboBox.addItem("Select type")
        for (type in huntPanel.model.types.sorted()) {
            typeComboBox.addItem(type)
        }
    }
}