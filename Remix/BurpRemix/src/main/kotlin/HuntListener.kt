package burp

class HuntListener(private val callbacks: IBurpExtenderCallbacks, private val huntTab: HuntTab) : IHttpListener {
    private val helpers: IExtensionHelpers = callbacks.helpers

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        messageInfo?.let { req ->
            HuntUtils(callbacks, huntTab.huntPanel).huntScan(req, toolFlag = toolFlag)
        }
    }
}