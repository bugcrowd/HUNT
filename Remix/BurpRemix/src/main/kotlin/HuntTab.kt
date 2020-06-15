package burp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.awt.FlowLayout
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
    private val rowSorter = TableRowSorter(model)

    init {
        HuntActions(this, callbacks)
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
                messageEditor.requestResponse = requestResponse
                requestViewer?.setMessage(requestResponse.request, true)
                responseViewer?.setMessage(requestResponse.response ?: ByteArray(0), false)
            }
        }

        val repeatPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        val repeatButton = JButton("Repeat Request")
        repeatButton.addActionListener { repeatRequest() }
        repeatPanel.add(repeatButton)

        val huntTable = JScrollPane(table)
        val reqResSplit =
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer?.component, responseViewer?.component)
        reqResSplit.resizeWeight = 0.5

        val repeatReqSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, repeatPanel, reqResSplit)

        val huntOptSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, huntOptions.panel, huntTable)

        panel.topComponent = huntOptSplit
        panel.bottomComponent = repeatReqSplit
        panel.resizeWeight = 0.5
        callbacks.customizeUiComponent(panel)
    }

    fun addHuntIssue(huntRequests: List<HuntIssue>) {
        for (huntRequest in huntRequests) {
            model.huntIssues.add(huntRequest)
            model.filterOrRefresh()
        }
    }

    private fun repeatRequest() {
        table.selectionModel.clearSelection()
        
        GlobalScope.launch(Dispatchers.IO) {
            val requestResponse = try {
                callbacks.makeHttpRequest(messageEditor.httpService, requestViewer?.message)
            } catch (e: java.lang.RuntimeException) {
                RequestResponse(requestViewer?.message, null, messageEditor.httpService)
            }
            withContext(Dispatchers.Swing) {
                SwingUtilities.invokeLater {
                    responseViewer?.setMessage(requestResponse?.response ?: ByteArray(0), false)
                }
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
            8 -> Short::class.java
            9 -> Integer::class.java
            10 -> String::class.java
            11 -> String::class.java
            12 -> String::class.java
            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {

        val huntIssue = displayedHuntIssues[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> huntIssue.dateTime
            2 -> huntIssue.host
            3 -> huntIssue.url.toString()
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


    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return when (columnIndex) {
            12 -> true
            else -> false
        }
    }

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

class RequestResponse(private var req: ByteArray?, private var res: ByteArray?, private var service: IHttpService?) :
    IHttpRequestResponse {

    override fun getComment(): String? = null

    override fun setComment(comment: String?) {}

    override fun getRequest(): ByteArray? = req

    override fun getHighlight(): String? = null

    override fun getHttpService(): IHttpService? = service

    override fun getResponse(): ByteArray? = res

    override fun setResponse(message: ByteArray?) {
        res = message
    }

    override fun setRequest(message: ByteArray?) {
        req = message
    }

    override fun setHttpService(httpService: IHttpService?) {
        service = httpService
    }

    override fun setHighlight(color: String?) {}
}

