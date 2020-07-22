package burp

class HuntListener(private val callbacks: IBurpExtenderCallbacks, private val huntTab: HuntTab) : IHttpListener {

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        messageInfo?.let { req ->
            if (!messageIsRequest) {
                HuntUtils(callbacks, huntTab.huntPanel).huntScan(req, toolFlag = toolFlag)
            }
        }
    }
}