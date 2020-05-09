package burp

import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class HuntListener(private val callbacks: IBurpExtenderCallbacks) : IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        val helpers = callbacks.helpers
        messageInfo?.let {
            if (messageIsRequest && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER)) {
                val request = helpers.analyzeRequest(messageInfo) ?: return
                val parameters = request.parameters
                val parameterNames =
                    parameters.asSequence().map { it.name }.map { checkParameterName(it) }.filterNotNull().map {
                        makeHuntRequest(
                            requestResponse = messageInfo,
                            parameter = it.first,
                            type = it.second
                        )
                    }.toList()
            }

        }
    }

    private fun checkParameterName(name: String): Pair<String, String>? {
        val huntData = HuntData()
        return when {
            huntData.insecureDirectObjectReference.contains(name) -> Pair(name, "Insecure Direct Object Reference")
            huntData.osCommandInjection.contains(name) -> Pair(name, "OS Command Injection")
            huntData.fileInclusionPathTraversal.contains(name) -> Pair(name, "File Inclusion and Path Traversal")
            huntData.sqlInjection.contains(name) -> Pair(name, "SQL Injection")
            huntData.serverSideRequestForgery.contains(name) -> Pair(name, "Server Side Request Forgery")
            huntData.serverSideTemplateInjection.contains(name) -> Pair(name, "Server Side Template Injection")
            huntData.debugLogicParameters.contains(name) -> Pair(name, "Debug and Logic Parameters")
            else -> null
        }
    }

    private fun makeHuntRequest(
        requestResponse: IHttpRequestResponse,
        parameter: String,
        type: String
    ): HuntRequests {
        val savedRequestResponse = callbacks.saveBuffersToTempFiles(requestResponse)
        val now = LocalDateTime.now()
        val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        val dateTime = now.format(dateFormatter) ?: ""
        val requestInfo = callbacks.helpers.analyzeRequest(requestResponse)
        val response = if (requestResponse.response != null) {
            callbacks.helpers.analyzeResponse(requestResponse.response)
        } else {
            null
        }

        return HuntRequests(
            requestResponse = savedRequestResponse,
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

data class HuntRequests(
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


