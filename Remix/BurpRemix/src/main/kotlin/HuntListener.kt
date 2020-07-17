package burp

class HuntListener(private val callbacks: IBurpExtenderCallbacks, private val huntTab: HuntTab) : IHttpListener {
    private val helpers: IExtensionHelpers = callbacks.helpers

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        messageInfo?.let { req ->
            val request = helpers.analyzeRequest(messageInfo) ?: return
            if (!messageIsRequest && callbacks.isInScope(request.url)
                && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER)
                && (request.method != "OPTIONS" || request.method != "HEAD")
            ) {
                HuntUtils(callbacks, toolFlag, huntTab).huntScan(req)
            }
        }
    }
}