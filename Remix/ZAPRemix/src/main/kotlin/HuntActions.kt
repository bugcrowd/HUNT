package org.zaproxy.zap.extension.hunt

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPopupMenu

class HuntActions(
    private val panel: HuntPanel
) : ActionListener {
    private val table = panel.table
    private val actionsMenu = JPopupMenu()
    private val copyURLs = JMenuItem("Copy URL(s)")
    private val deleteMenu = JMenuItem("Delete HUNT Issue(s)")
    private val clearMenu = JMenuItem("Clear HUNT Issues")
    private val comments = JMenuItem("Add comment")
    private val details = JMenuItem("Details")

    init {
        copyURLs.addActionListener(this)
        deleteMenu.addActionListener(this)
        clearMenu.addActionListener(this)
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
            }
            copyURLs -> {
                val urls = selectedHuntIssues.joinToString { it.url }
                val clipboard: Clipboard = Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(StringSelection(urls), null)
            }
            else -> {
                for (selectedHuntIssue in selectedHuntIssues) {
                    when (source) {
                        comments -> {
                            val newComments = JOptionPane.showInputDialog("Comments:", selectedHuntIssue.comments)
                            selectedHuntIssue.comments = newComments
                            panel.model.refreshHunt()
                        }
                        details -> {
                            selectedHuntIssue.types.forEach { type ->
                                val details = HuntData().namesDetails[type]
                                    ?.replace("%PARAM%", "'${selectedHuntIssue.parameter}'")
                                    ?.replace("%URL%", "'${selectedHuntIssue.url}'")
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
}
