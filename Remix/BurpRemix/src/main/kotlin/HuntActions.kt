package burp

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPopupMenu

class HuntActions(
        private val panel: HuntPanel,
        private val callbacks: IBurpExtenderCallbacks
) : ActionListener {
    private val table = panel.table
    private val actionsMenu = JPopupMenu()
    private val sendToRepeater = JMenuItem("Send request(s) to Repeater")
    private val sendToIntruder = JMenuItem("Send request(s) to Intruder")
    private val copyURLs = JMenuItem("Copy URL(s)")
    private val deleteMenu = JMenuItem("Delete Hunt Issue(s)")
    private val clearMenu = JMenuItem("Clear Hunt Issues")
    private val comments = JMenuItem("Add comment")
    private val details = JMenuItem("Details")

    init {
        sendToRepeater.addActionListener(this)
        sendToIntruder.addActionListener(this)
        copyURLs.addActionListener(this)
        deleteMenu.addActionListener(this)
        clearMenu.addActionListener(this)
        actionsMenu.add(sendToRepeater)
        actionsMenu.add(sendToIntruder)
        actionsMenu.add(copyURLs)
        actionsMenu.addSeparator()
        actionsMenu.add(deleteMenu)
        actionsMenu.add(clearMenu)
        actionsMenu.addSeparator()
        comments.addActionListener(this)
        details.addActionListener(this)
        actionsMenu.addSeparator()
        actionsMenu.add(comments)
        actionsMenu.add(details)
        panel.table.componentPopupMenu = actionsMenu
    }


    override fun actionPerformed(e: ActionEvent?) {
        if (table.selectedRow == -1) return
        val selectedHuntIssues = getSelectedHuntIssues()
        when (val source = e?.source) {
            deleteMenu -> {
                panel.model.removeHuntIssues(selectedHuntIssues)
            }
            clearMenu -> {
                panel.model.clearHunt()
                panel.requestViewer?.setMessage(ByteArray(0), true)
                panel.responseViewer?.setMessage(ByteArray(0), false)
            }
            copyURLs -> {
                val urls = selectedHuntIssues.map { it.url }.joinToString()
                val clipboard: Clipboard = Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(StringSelection(urls), null)
            }
            else -> {
                for (selectedHuntIssue in selectedHuntIssues) {
                    val https = useHTTPs(selectedHuntIssue)
                    val url = selectedHuntIssue.url
                    when (source) {
                        sendToRepeater -> {
                            var title = selectedHuntIssue.types.first()
                            if (title.length > 10) {
                                title = title.substring(0, 9) + "+"
                            } else if (title.isBlank()) {
                                title = selectedHuntIssue.types.first()
                            }
                            callbacks.sendToRepeater(
                                    url.host,
                                    url.port,
                                    https,
                                    selectedHuntIssue.requestResponse.request,
                                    title
                            )
                        }
                        sendToIntruder -> {
                            callbacks.sendToIntruder(
                                    url.host, url.port, https,
                                    selectedHuntIssue.requestResponse.request, null
                            )
                        }
                        comments -> {
                            val newComments = JOptionPane.showInputDialog("Comments:", selectedHuntIssue.comments)
                            selectedHuntIssue.comments = newComments
                            panel.model.refreshHunt()
                        }
                        details -> {
                            selectedHuntIssue.types.forEach { type ->
                                val details = HuntData().namesDetails[type]
                                        ?.replace("%PARAM%", "'${selectedHuntIssue.parameter}'")?.replace("%URL%", "'${selectedHuntIssue.url}'")
                                JOptionPane.showMessageDialog(null, details)
                            }
                        }
                    }
                }
            }
        }
    }


    private fun getSelectedHuntIssues(): MutableList<HuntIssue> {
        val selectedHuntIssue: MutableList<HuntIssue> = ArrayList()
        for (index in table.selectedRows) {
            val row = table.convertRowIndexToModel(index)
            selectedHuntIssue.add(panel.model.displayedHuntIssues[row])
        }
        return selectedHuntIssue
    }

    private fun useHTTPs(huntIssue: HuntIssue): Boolean {
        return (huntIssue.url.protocol.toLowerCase() == "https")

    }
}
