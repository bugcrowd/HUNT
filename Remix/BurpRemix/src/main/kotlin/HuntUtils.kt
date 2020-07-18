package burp

import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class HuntUtils(
    private val callbacks: IBurpExtenderCallbacks,
    private val huntPanel: HuntPanel
) {
    private val helpers: IExtensionHelpers = callbacks.helpers

    fun huntScan(
        messageInfo: IHttpRequestResponse,
        toolFlag: Int = IBurpExtenderCallbacks.TOOL_PROXY,
        duplicates: Boolean = true
    ) {
        val request = helpers.analyzeRequest(messageInfo) ?: return

        if (callbacks.isInScope(request.url)
            && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER)
            && (request.method != "OPTIONS" || request.method != "HEAD")
        ) {

            val noDuplicates = !duplicates || huntPanel.huntFilters.huntOptions.noDuplicateIssues.isSelected
            val highlightProxyHistory = huntPanel.huntFilters.huntOptions.highlightProxyHistory.isSelected

            val huntIssues = huntScannerIssues(messageInfo)?.filterNot {
                noDuplicates && checkIfDuplicate(it)
            } ?: return

            if (huntIssues.isNotEmpty()) {
                huntPanel.addHuntIssue(huntIssues)
                if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && highlightProxyHistory) {
                    messageInfo.highlight = "cyan"
                    messageInfo.comment =
                        "HUNT: ${huntIssues.map { issue -> issue.types }.flatten().toSet().joinToString()}"
                }
            }
        }
    }

    private fun huntScannerIssues(messageInfo: IHttpRequestResponse): List<HuntIssue>? {
        val requestInfo = helpers.analyzeRequest(messageInfo) ?: return null
        val parameters = requestInfo.parameters.map { it.name.toLowerCase() }.sorted()

        return parameters.asSequence().map { param -> checkParameterName(param) }
            .filterNotNull().filter { !it.second.isNullOrEmpty() }.map {
                makeHuntRequest(
                    requestResponse = messageInfo,
                    parameter = it.first,
                    types = it.second,
                    allParameters = parameters
                )
            }.toList()
    }

    private fun checkParameterName(param: String) =
        Pair(param, HuntData().huntParams.asSequence().filter { it.params.contains(param) }.map { it.name }.toSet())

    private fun makeHuntRequest(
        requestResponse: IHttpRequestResponse,
        parameter: String,
        types: Set<String>,
        allParameters: List<String>
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
            comments = requestResponse.comment ?: "",
            allParameters = allParameters
        )
    }

    private fun getTitle(response: ByteArray?): String {
        if (response == null) return ""
        val html = callbacks.helpers.bytesToString(response)
        val titleRegex = "<title>(.*?)</title>".toRegex()
        val title = titleRegex.find(html)?.value ?: ""
        return title.removePrefix("<title>").removeSuffix("</title>")
    }

    private fun checkIfDuplicate(huntIssue: HuntIssue): Boolean {
        return if (huntPanel.huntFilters.huntOptions.ignoreHostDuplicates.isSelected) {
            huntPanel.huntIssues.any { it.url.path == huntIssue.url.path && it.parameter == huntIssue.parameter }
        } else {
            huntPanel.huntIssues.any { it.url.host == huntIssue.url.host && it.url.path == huntIssue.url.path && it.parameter == huntIssue.parameter }
        }
    }

    fun importProxyHistory() {
        callbacks.proxyHistory.forEach {
            huntScan(it, duplicates = false)
        }
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
    var comments: String,
    val allParameters: List<String>
)