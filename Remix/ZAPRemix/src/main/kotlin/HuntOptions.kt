package org.zaproxy.zap.extension.hunt

import java.awt.FlowLayout
import javax.swing.*


class HuntOptions(
    private val huntPanel: HuntPanel
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    private val filterBar = JTextField("", 20)
    private val filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))
    private val typeComboBox = JComboBox(arrayOf<String>())

    init {
        val clearButton = JButton("Clear Issues")
        val filterLabel = JLabel("Filter HUNT Issues:")
        val filterButton = JButton("Filter")
        val resetButton = JButton("Reset")
        val typeLabel = JLabel("Types:")
        typeComboBox.prototypeDisplayValue = "File Inclusion and Path Traversal  "
        clearButton.addActionListener { clearHuntIssues() }
        filterBar.addActionListener { filterHuntIssues() }
        filterButton.addActionListener { filterHuntIssues() }
        resetButton.addActionListener { resetFilter() }
        filterPanel.add(filterLabel)
        filterPanel.add(filterBar)
        filterPanel.add(typeLabel)
        filterPanel.add(typeComboBox)
        filterPanel.add(filterButton)
        filterPanel.add(resetButton)
        loadPanel.add(clearButton)
        panel.leftComponent = filterPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }

    fun filtered(): Boolean {
        return if (typeComboBox.selectedItem != "All" || filterBar.text.isNotEmpty()) {
            filterHuntIssues()
            true
        } else {
            false
        }
    }

    private fun filterHuntIssues() {
        val selectedType = typeComboBox.selectedItem ?: "All"
        SwingUtilities.invokeLater {
            val searchText = filterBar.text.toLowerCase()
            var filteredHuntIssues = this.huntPanel.model.huntIssues
            filteredHuntIssues = filterTypes(filteredHuntIssues)
            if (searchText.isNotEmpty()) {
                filteredHuntIssues = filteredHuntIssues
                    .filter {
                        it.comments.toLowerCase().contains(searchText) ||
                                it.url.toLowerCase().contains(searchText) ||
                                it.requestResponse.requestBody.toString().toLowerCase().contains(
                                    searchText
                                ) ||
                                it.requestResponse.responseBody.toString().toLowerCase().contains(
                                    searchText
                                )
                    }.toMutableList()
            }
            huntPanel.model.refreshHunt(filteredHuntIssues)
            if (selectedType != "All") {
                typeComboBox.selectedItem = selectedType
            }
        }
    }

    private fun filterTypes(huntIssues: MutableList<HuntIssue>): MutableList<HuntIssue> {
        val selectedType = typeComboBox.selectedItem ?: "All"
        return if (selectedType != "All") {
            val type = typeComboBox.selectedItem
            huntIssues
                .filter {
                    it.types.contains(HuntData().nameToShortName[type])
                }.toMutableList()
        } else {
            huntIssues
        }
    }

    private fun resetFilter() {
        filterBar.text = ""
        huntPanel.model.refreshHunt()
        updateTypes()
    }

    private fun clearHuntIssues() {
        huntPanel.model.clearHunt()
    }

    fun updateTypes() {
        typeComboBox.removeAllItems()
        typeComboBox.addItem("All")
        for (type in huntPanel.model.types.sorted()) {
            typeComboBox.addItem(type)
        }
    }
}