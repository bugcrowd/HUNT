package burp

import javax.swing.SwingUtilities

class BurpExtender : IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        val tab = HuntTab(callbacks)
        callbacks.apply {
            registerHttpListener(HuntListener(callbacks, tab))
            stdout.apply {
                write("HUNT - v2.3".toByteArray())
                write("\nOriginally by: JP Villanueva, Jason Haddix and team at Bugcrowd".toByteArray())
                write("\nRepo: https://github.com/bugcrowd/HUNT".toByteArray())
                write("\nRemixed by: Caleb (cak) Kinney (derail.io)".toByteArray())
            }
            setExtensionName("HUNT")
        }

        SwingUtilities.invokeLater {
            callbacks.addSuiteTab(tab)
            if ((callbacks.loadExtensionSetting(HuntOptions.IMPORT_PROXY_ON_START) ?: "true").toBoolean()) {
                HuntUtils(callbacks, tab.huntPanel).importProxyHistory()
            }
        }
    }
}