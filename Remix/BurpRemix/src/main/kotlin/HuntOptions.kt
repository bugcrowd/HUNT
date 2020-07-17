package burp

import java.awt.BorderLayout
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JFrame
import javax.swing.JPanel

class HuntOptions(callbacks: IBurpExtenderCallbacks) {
    val optionFrame = JFrame("HUNT Options")
    val fetchHistoryOnStart = JCheckBox("Fetch proxy history on start")
    val noDuplicateIssues = JCheckBox("Do not add duplicate issues")

    init {
        val optionsPanel = JPanel()
        fetchHistoryOnStart.isSelected = (callbacks.loadExtensionSetting(IMPORT_PROXY_ON_START) ?: "false").toBoolean()
        noDuplicateIssues.isSelected = (callbacks.loadExtensionSetting(NO_DUP_ISSUES) ?: "true").toBoolean()
        fetchHistoryOnStart.addActionListener {
            callbacks.saveExtensionSetting(
                IMPORT_PROXY_ON_START,
                fetchHistoryOnStart.isSelected.toString()
            )
        }
        noDuplicateIssues.addActionListener {
            callbacks.saveExtensionSetting(
                NO_DUP_ISSUES,
                noDuplicateIssues.isSelected.toString()
            )
        }
        optionsPanel.layout = BoxLayout(optionsPanel, BoxLayout.Y_AXIS)
        optionsPanel.add(fetchHistoryOnStart)
        optionsPanel.add(noDuplicateIssues)
        optionFrame.defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        optionFrame.contentPane.add(optionsPanel, BorderLayout.CENTER)
        optionFrame.setLocationRelativeTo(null)
        optionFrame.pack()
    }

    companion object {
        const val IMPORT_PROXY_ON_START = "import proxy on start"
        const val NO_DUP_ISSUES = "no dup issues"
    }
}