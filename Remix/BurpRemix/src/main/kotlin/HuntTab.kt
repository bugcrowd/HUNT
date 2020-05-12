package burp

import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableRowSorter

class HuntTab(callbacks: IBurpExtenderCallbacks) : ITab {
    val huntTable = HuntPanel(callbacks)

    override fun getTabCaption() = "HUNT RMX"

    override fun getUiComponent() = huntTable.panel
}

class HuntPanel(private val callbacks: IBurpExtenderCallbacks) {
    private val huntOptions = HuntOptions(this, callbacks)
    val model = HuntModel(huntOptions)
    val table = JTable(model)

    private val messageEditor = MessageEditor(callbacks)
    val requestViewer: IMessageEditor? = messageEditor.requestViewer
    val responseViewer: IMessageEditor? = messageEditor.responseViewer

    val panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
    val huntIssues = model.huntIssues


    init {
        HuntActions(this, huntIssues, callbacks)
        table.autoResizeMode = JTable.AUTO_RESIZE_OFF
        table.columnModel.getColumn(0).preferredWidth = 30 // ID
        table.columnModel.getColumn(1).preferredWidth = 145 // date
        table.columnModel.getColumn(2).preferredWidth = 125 // host
        table.columnModel.getColumn(3).preferredWidth = 250 // url
        table.columnModel.getColumn(4).preferredWidth = 200 // type
        table.columnModel.getColumn(5).preferredWidth = 75 // parameter
        table.columnModel.getColumn(6).preferredWidth = 100 // title
        table.columnModel.getColumn(7).preferredWidth = 50 // method
        table.columnModel.getColumn(8).preferredWidth = 50 // status
        table.columnModel.getColumn(9).preferredWidth = 50 // length
        table.columnModel.getColumn(10).preferredWidth = 50 // mime
        table.columnModel.getColumn(11).preferredWidth = 50 // protocol
        table.columnModel.getColumn(12).preferredWidth = 80 // file
        table.columnModel.getColumn(13).preferredWidth = 120 // comments
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.rowSorter = TableRowSorter(model)
        table.autoscrolls = true

        table.selectionModel.addListSelectionListener {
            if (table.selectedRow != -1) {
                val displayedHuntIssues = model.displayedHuntIssues
                val selectedRow = table.convertRowIndexToModel(table.selectedRow)
                val requestResponse = displayedHuntIssues[selectedRow].requestResponse
                messageEditor.requestResponse = requestResponse
                requestViewer?.setMessage(requestResponse.request, true)
                responseViewer?.setMessage(requestResponse.response ?: ByteArray(0), false)
            }
        }

        val huntTable = JScrollPane(table)
        val reqResSplit =
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer?.component, responseViewer?.component)
        reqResSplit.resizeWeight = 0.5

        val huntOptSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, huntOptions.panel, huntTable)

        panel.topComponent = huntOptSplit
        panel.bottomComponent = reqResSplit
        panel.resizeWeight = 0.5
        callbacks.customizeUiComponent(panel)
    }

    fun addHuntIssue(huntRequests: List<HuntIssue>) {
        for (huntRequest in huntRequests) {
            model.addHuntDetails(huntRequest)

            SwingUtilities.invokeLater {
                table.scrollRectToVisible(table.getCellRect(table.rowCount - 1, 0, true))
                table.setRowSelectionInterval(table.rowCount - 1, table.rowCount - 1)
            }
        }
    }

}

class MessageEditor(callbacks: IBurpExtenderCallbacks) : IMessageEditorController {
    var requestResponse: IHttpRequestResponse? = null

    val requestViewer: IMessageEditor? = callbacks.createMessageEditor(this, true)
    val responseViewer: IMessageEditor? = callbacks.createMessageEditor(this, false)

    override fun getResponse(): ByteArray? = requestResponse?.response ?: ByteArray(0)

    override fun getRequest(): ByteArray? = requestResponse?.request

    override fun getHttpService(): IHttpService? = requestResponse?.httpService
}

class HuntModel(private val huntOptions: HuntOptions) : AbstractTableModel() {
    private val columns =
        listOf(
            "ID",
            "Added",
            "Host",
            "URL",
            "Type",
            "Param",
            "Title",
            "Method",
            "Status",
            "Length",
            "MIME",
            "Protocol",
            "File",
            "Comments"
        )
    var huntIssues: MutableList<HuntIssue> = ArrayList()
    var types: List<String> = listOf()
    var displayedHuntIssues: MutableList<HuntIssue> = ArrayList()
        private set

    override fun getRowCount(): Int = displayedHuntIssues.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String {
        return columns[column]
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when (columnIndex) {
            0 -> java.lang.Integer::class.java
            1 -> String::class.java
            2 -> String::class.java
            3 -> String::class.java
            4 -> String::class.java
            5 -> String::class.java
            6 -> String::class.java
            7 -> String::class.java
            8 -> String::class.java
            9 -> String::class.java
            10 -> String::class.java
            11 -> String::class.java
            12 -> String::class.java
            13 -> String::class.java
            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val huntIssues = displayedHuntIssues[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> huntIssues.dateTime
            2 -> huntIssues.host
            3 -> huntIssues.url.toString()
            4 -> huntIssues.type
            5 -> huntIssues.parameter
            6 -> huntIssues.title
            7 -> huntIssues.method
            8 -> huntIssues.statusCode
            9 -> huntIssues.length
            10 -> huntIssues.mimeType
            11 -> huntIssues.protocol
            12 -> huntIssues.file
            13 -> huntIssues.comments
            else -> ""
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return when (columnIndex) {
            13 -> true
            else -> false
        }
    }

    fun addHuntDetails(huntIssue: HuntIssue) {
        huntIssues.add(huntIssue)
        displayedHuntIssues = huntIssues
        fireTableRowsInserted(displayedHuntIssues.lastIndex, displayedHuntIssues.lastIndex)
        refreshHunt()
    }

    fun removeHuntIssues(selectedHuntIssues: MutableList<HuntIssue>) {
        huntIssues.removeAll(selectedHuntIssues)
        refreshHunt()
    }

    fun clearHunt() {
        huntIssues.clear()
        refreshHunt()
    }

    fun refreshHunt(updatedHuntIssues: MutableList<HuntIssue> = huntIssues) {
        displayedHuntIssues = updatedHuntIssues
        fireTableDataChanged()
        updateTypes()
    }

    private fun updateTypes() {
        val newTypes = displayedHuntIssues.map { it.type }.toSet().toList()
        types = newTypes
        huntOptions.updateTypes()
    }

}


