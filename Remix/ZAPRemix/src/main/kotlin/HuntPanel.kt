package org.zaproxy.zap.extension.hunt

import org.parosproxy.paros.extension.AbstractPanel
import org.parosproxy.paros.view.View
import java.awt.BorderLayout
import java.lang.IndexOutOfBoundsException
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableRowSorter

class HuntPanel : AbstractPanel() {
    private val huntOptions = HuntOptions(this)
    val model = HuntModel(huntOptions)
    val table = JTable(model)

    private val panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
    private val rowSorter = TableRowSorter(model)

    init {
        HuntActions(this)
        table.autoResizeMode = JTable.AUTO_RESIZE_ALL_COLUMNS
        table.columnModel.getColumn(0).preferredWidth = 50 // ID
        table.columnModel.getColumn(1).preferredWidth = 160 // date
        table.columnModel.getColumn(2).preferredWidth = 125 // host
        table.columnModel.getColumn(3).preferredWidth = 250 // url
        table.columnModel.getColumn(4).preferredWidth = 150 // type
        table.columnModel.getColumn(5).preferredWidth = 75 // parameter
        table.columnModel.getColumn(6).preferredWidth = 150 // title
        table.columnModel.getColumn(7).preferredWidth = 50 // method
        table.columnModel.getColumn(8).preferredWidth = 50 // status
        table.columnModel.getColumn(9).preferredWidth = 50 // length
        table.columnModel.getColumn(10).preferredWidth = 50 // mime
        table.columnModel.getColumn(11).preferredWidth = 50 // protocol
        table.columnModel.getColumn(12).preferredWidth = 120 // comments
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.rowSorter = rowSorter
        table.autoscrolls = true
        table.autoCreateRowSorter = true

        table.selectionModel.addListSelectionListener {
            if (table.selectedRow != -1) {
                val displayedHuntIssues = model.displayedHuntIssues
                val selectedRow = table.convertRowIndexToModel(table.selectedRow)
                val requestResponse = displayedHuntIssues[selectedRow].requestResponse
                View.getSingleton().displayMessage(requestResponse)
                displayedHuntIssues[selectedRow].highlighter.highlight()
            }
        }

        val huntTable = JScrollPane(table)
        panel.topComponent = huntOptions.panel
        panel.bottomComponent = huntTable
        name = "HUNT"
        layout = BorderLayout()
        add(panel)
    }

    fun addHuntIssue(huntRequests: List<HuntIssue>) {
        for (huntRequest in huntRequests) {
            model.huntIssues.add(huntRequest)
            model.filterOrRefresh()
        }
    }
}

class HuntModel(private val huntOptions: HuntOptions) : AbstractTableModel() {
    private val columns =
        listOf(
            "ID",
            "Added",
            "Host",
            "URL",
            "Types",
            "Param",
            "Title",
            "Method",
            "Status",
            "Length",
            "MIME",
            "Protocol",
            "Comments"
        )
    var huntIssues: MutableList<HuntIssue> = ArrayList()
    var types: List<String> = listOf()
    var displayedHuntIssues: MutableList<HuntIssue> = ArrayList()
        private set

    companion object {
        private const val COMMENTS = 12
    }

    override fun getRowCount(): Int = displayedHuntIssues.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String {
        return columns[column]
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when (columnIndex) {
            0 -> java.lang.Integer::class.java
            in 1..7 -> String::class.java
            in 8..9 -> Integer::class.java
            in 10..12 -> String::class.java
            else -> throw IndexOutOfBoundsException("$columnIndex is out of bounds")
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {

        val huntIssue = displayedHuntIssues[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> huntIssue.dateTime
            2 -> huntIssue.host
            3 -> huntIssue.url
            4 -> huntIssue.types.joinToString()
            5 -> huntIssue.parameter
            6 -> huntIssue.title
            7 -> huntIssue.method
            8 -> huntIssue.statusCode
            9 -> huntIssue.length
            10 -> huntIssue.mimeType
            11 -> huntIssue.protocol
            12 -> huntIssue.comments
            else -> ""
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int) = columnIndex == COMMENTS

    override fun setValueAt(value: Any?, rowIndex: Int, colIndex: Int) {
        val huntIssue: HuntIssue = huntIssues[rowIndex]
        when (colIndex) {
            12 -> huntIssue.comments = value.toString()
            else -> return
        }
        filterOrRefresh()
    }

    fun removeHuntIssues(selectedHuntIssues: MutableList<HuntIssue>) {
        huntIssues.removeAll(selectedHuntIssues)
        filterOrRefresh()
    }

    fun clearHunt() {
        huntIssues.clear()
        filterOrRefresh()
    }

    fun filterOrRefresh() {
        if (!huntOptions.filtered()) {
            refreshHunt()
        }
    }

    fun refreshHunt(updatedHuntIssues: MutableList<HuntIssue> = huntIssues) {
        displayedHuntIssues = updatedHuntIssues
        fireTableDataChanged()
        updateTypes()
    }

    private fun updateTypes() {
        val shortToName = HuntData().shortToName
        val newTypes = displayedHuntIssues.flatMap { it.types }.mapNotNull { shortToName[it] }.toSet().toList()
        types = newTypes
        huntOptions.updateTypes()
    }
}