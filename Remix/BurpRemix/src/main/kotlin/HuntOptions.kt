package burp

import java.awt.BorderLayout
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JFrame
import javax.swing.JPanel

class HuntOptions(callbacks: IBurpExtenderCallbacks) {
    val optionFrame = JFrame("HUNT Options")
    private val fetchHistoryOnStart = JCheckBox("Fetch proxy history on start")
    val noDuplicateIssues = JCheckBox("Ignore duplicate issues")
    val ignoreHostDuplicates = JCheckBox("Ignore host when considering duplicate issues")
    val highlightProxyHistory = JCheckBox("Highlight proxy history")


    init {
        val optionsPanel = JPanel()
        fetchHistoryOnStart.isSelected = (callbacks.loadExtensionSetting(IMPORT_PROXY_ON_START) ?: "true").toBoolean()
        noDuplicateIssues.isSelected = (callbacks.loadExtensionSetting(NO_DUP_ISSUES) ?: "true").toBoolean()
        ignoreHostDuplicates.isSelected = (callbacks.loadExtensionSetting(IGNORE_HOST_DUPLICATES)
                ?: "false").toBoolean()
        highlightProxyHistory.isSelected =
                (callbacks.loadExtensionSetting(HIGHLIGHT_PROXY_HISTORY) ?: "false").toBoolean()

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
        ignoreHostDuplicates.addActionListener {
            callbacks.saveExtensionSetting(
                    IGNORE_HOST_DUPLICATES,
                    ignoreHostDuplicates.isSelected.toString()
            )
        }
        highlightProxyHistory.addActionListener {
            callbacks.saveExtensionSetting(
                    HIGHLIGHT_PROXY_HISTORY,
                    highlightProxyHistory.isSelected.toString()
            )
        }
        optionsPanel.layout = BoxLayout(optionsPanel, BoxLayout.Y_AXIS)
        optionsPanel.add(fetchHistoryOnStart)
        optionsPanel.add(noDuplicateIssues)
        optionsPanel.add(ignoreHostDuplicates)
        optionsPanel.add(highlightProxyHistory)
        optionFrame.defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        optionFrame.contentPane.add(optionsPanel, BorderLayout.CENTER)
        optionFrame.setLocationRelativeTo(null)
        optionFrame.pack()
    }

    companion object {
        const val IMPORT_PROXY_ON_START = "import proxy on start"
        const val NO_DUP_ISSUES = "no dup issues"
        const val HIGHLIGHT_PROXY_HISTORY = "highlight proxy history"
        const val IGNORE_HOST_DUPLICATES = "ignore host on duplicates"
    }
}