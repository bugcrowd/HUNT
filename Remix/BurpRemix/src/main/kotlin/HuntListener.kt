package burp

import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter


class HuntListener(private val callbacks: IBurpExtenderCallbacks, private val huntTab: HuntTab) : IHttpListener {
    private val helpers: IExtensionHelpers = callbacks.helpers

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        messageInfo?.let {
            if (!messageIsRequest && (callbacks.isInScope(helpers.analyzeRequest(messageInfo).url)) && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER)) {
                val request = helpers.analyzeRequest(messageInfo) ?: return
                val parameters = request.parameters
                val huntIssues =
                    parameters.asSequence().map { it.name }.map { checkParameterName(it.toLowerCase()) }.filterNotNull()
                        .map {
                            makeHuntRequest(
                                requestResponse = messageInfo,
                                parameter = it.first,
                                type = it.second
                            )
                        }.toList()

                huntTab.huntTable.addHuntIssue(huntIssues)
            }

        }
    }

    private fun checkParameterName(name: String): Pair<String, String>? {
        val huntData = HuntData()
        return when {
            huntData.insecureDirectObjectReference.params.contains(name) -> Pair(
                name,
                huntData.insecureDirectObjectReference.name
            )
            huntData.osCommandInjection.params.contains(name) -> Pair(name, huntData.osCommandInjection.name)
            huntData.fileInclusionPathTraversal.params.contains(name) -> Pair(
                name,
                huntData.fileInclusionPathTraversal.name
            )
            huntData.sqlInjection.params.contains(name) -> Pair(name, huntData.sqlInjection.name)
            huntData.serverSideRequestForgery.params.contains(name) -> Pair(
                name,
                huntData.serverSideRequestForgery.name
            )
            huntData.serverSideTemplateInjection.params.contains(name) -> Pair(
                name,
                huntData.serverSideTemplateInjection.name
            )
            huntData.debugLogicParameters.params.contains(name) -> Pair(name, huntData.debugLogicParameters.name)
            else -> null
        }
    }

    private fun makeHuntRequest(
        requestResponse: IHttpRequestResponse,
        parameter: String,
        type: String
    ): HuntIssue {
        val now = LocalDateTime.now()
        val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        val dateTime = now.format(dateFormatter) ?: ""
        val requestInfo = callbacks.helpers.analyzeRequest(requestResponse)
        val response = if (requestResponse.response != null) {
            callbacks.helpers.analyzeResponse(requestResponse.response)
        } else {
            null
        }


        return HuntIssue(
            requestResponse = callbacks.saveBuffersToTempFiles(requestResponse),
            dateTime = dateTime,
            host = requestInfo.url.host,
            url = requestInfo.url,
            type = type,
            parameter = parameter,
            method = requestInfo?.method ?: "",
            statusCode = response?.statusCode?.toString() ?: "",
            title = getTitle(requestResponse.response),
            length = requestResponse.response?.size?.toString() ?: "",
            mimeType = response?.inferredMimeType ?: "",
            protocol = requestInfo?.url?.protocol ?: "",
            file = requestInfo?.url?.file ?: "",
            comments = requestResponse.comment ?: ""
        )
    }

    private fun getTitle(response: ByteArray?): String {
        if (response == null) return ""
        val html = callbacks.helpers.bytesToString(response)
        val titleRegex = "<title>(.*?)</title>".toRegex()
        val title = titleRegex.find(html)?.value ?: ""
        return title.removePrefix("<title>").removeSuffix("</title>")
    }
}

data class HuntIssue(
    val requestResponse: IHttpRequestResponsePersisted,
    val dateTime: String,
    val host: String,
    val url: URL,
    var type: String,
    val parameter: String,
    val method: String,
    val statusCode: String,
    val title: String,
    val length: String,
    val mimeType: String,
    val protocol: String,
    val file: String,
    var comments: String
)


