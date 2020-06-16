package org.zaproxy.zap.extension.hunt

import org.parosproxy.paros.extension.ExtensionAdaptor
import org.parosproxy.paros.extension.ExtensionHook
import org.parosproxy.paros.network.HttpSender
import java.awt.EventQueue

class ExtensionHunt : ExtensionAdaptor(NAME) {
    private val huntPanel = HuntPanel()
    private val huntListener = HuntListener(huntPanel)

    companion object {
        const val NAME = "HUNT"
    }

    override fun hook(extensionHook: ExtensionHook?) {
        super.hook(extensionHook)
        if (view != null) {
            HttpSender.addListener(huntListener)
            extensionHook?.hookView?.addStatusPanel(huntPanel)
        }
    }

    override fun unload() {
        HttpSender.removeListener(huntListener)
    }

    override fun canUnload(): Boolean = true

    override fun getAuthor(): String = "Caleb Kinney"

    override fun getDescription(): String = "HUNT Scanner"

    override fun postInstall() {
        super.postInstall()

        if (view != null) {
            EventQueue.invokeLater {
                huntPanel.setTabFocus()
            }
        }
    }
}
