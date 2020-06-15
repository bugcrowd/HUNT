package burp

import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter


class HuntListener(private val callbacks: IBurpExtenderCallbacks, private val huntTab: HuntTab) : IHttpListener {
    private val helpers: IExtensionHelpers = callbacks.helpers

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        messageInfo?.let {
            val request = helpers.analyzeRequest(messageInfo) ?: return
            if (!messageIsRequest && callbacks.isInScope(request.url)
                && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER)
                && (request.method != "OPTIONS" || request.method != "HEAD")
            ) {
                val requestInfo = helpers.analyzeRequest(messageInfo) ?: return
                val parameters = requestInfo.parameters
                val huntIssues =
                    parameters.asSequence().map { param -> checkParameterName(param.name.toLowerCase()) }
                        .filterNotNull().filter { !it.second.isNullOrEmpty() }.map {
                            makeHuntRequest(
                                requestResponse = messageInfo,
                                parameter = it.first,
                                types = it.second
                            )
                        }.toList()

                huntTab.huntTable.addHuntIssue(huntIssues)
                if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
                    messageInfo.highlight = "cyan"
                    messageInfo.comment = "HUNT: ${huntIssues.map { it.types }.flatten().toSet().joinToString()}"
                }
            }
        }
    }

    private fun checkParameterName(param: String) =
        Pair(param, HuntData().huntParams.asSequence().filter { it.params.contains(param) }.map { it.name }.toSet())

    private fun makeHuntRequest(
        requestResponse: IHttpRequestResponse,
        parameter: String,
        types: Set<String>
    ): HuntIssue {
        val now = LocalDateTime.now()
        val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        val dateTime = now.format(dateFormatter) ?: ""
        val typeNames = types.map { HuntData().nameToShortName[it] ?: it }.toSet()
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
            types = typeNames,
            parameter = parameter,
            method = requestInfo?.method ?: "",
            statusCode = response?.statusCode ?: 0,
            title = getTitle(requestResponse.response),
            length = requestResponse.response?.size ?: 0,
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
    val types: Set<String>,
    val parameter: String,
    val method: String,
    val statusCode: Short,
    val title: String,
    val length: Int,
    val mimeType: String,
    val protocol: String,
    val file: String,
    var comments: String
)


