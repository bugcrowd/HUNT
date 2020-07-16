package org.zaproxy.zap.extension.hunt

import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpSender
import org.zaproxy.zap.network.HttpSenderListener
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class HuntListener(private val huntPanel: HuntPanel) : HttpSenderListener {
    override fun onHttpResponseReceive(msg: HttpMessage?, initiator: Int, sender: HttpSender?) {
        msg?.let { request ->
            if (request.isInScope
                && (request.requestHeader.method != "OPTIONS" || request.requestHeader.method != "HEAD")
            ) {
                val parameters = request.paramNames
                val huntIssues =
                    parameters.asSequence().map { param -> checkParameterName(param.toLowerCase()) }
                        .filterNotNull().filter { !it.second.isNullOrEmpty() }.map {
                            makeHuntRequest(
                                requestResponse = request,
                                parameter = it.first,
                                types = it.second
                            )
                        }.toList()

                huntPanel.addHuntIssue(huntIssues)
            }
        }
    }

    private fun checkParameterName(param: String) =
        Pair(param, HuntData().huntParams.asSequence().filter { it.params.contains(param) }.map { it.name }.toSet())

    private fun makeHuntRequest(
        requestResponse: HttpMessage,
        parameter: String,
        types: Set<String>
    ): HuntIssue {
        val now = LocalDateTime.now()
        val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        val dateTime = now.format(dateFormatter) ?: ""
        val typeNames = types.map { HuntData().nameToShortName[it] ?: it }.toSet()

        return HuntIssue(
            requestResponse = requestResponse,
            dateTime = dateTime,
            host = requestResponse.requestHeader?.uri?.host ?: "",
            url = requestResponse.requestHeader?.uri.toString(),
            types = typeNames,
            parameter = parameter,
            method = requestResponse.requestHeader?.method ?: "",
            statusCode = requestResponse.responseHeader.statusCode,
            title = getTitle(requestResponse.responseBody.toString()),
            length = requestResponse.responseHeader.contentLength,
            mimeType = requestResponse.responseHeader.getHeaderValues(HttpHeader.CONTENT_TYPE).toString(),
            protocol = requestResponse.requestHeader.uri.scheme,
            highlighter = HuntHighlight(requestResponse, parameter)

        )
    }

    private fun getTitle(responseBody: String): String {
        val titleRegex = "<title>(.*?)</title>".toRegex()
        val title = titleRegex.find(responseBody)?.value ?: ""
        return title.removePrefix("<title>").removeSuffix("</title>")
    }

    override fun getListenerOrder() = 0

    override fun onHttpRequestSend(msg: HttpMessage?, initiator: Int, sender: HttpSender?) {}
}

data class HuntIssue(
    val requestResponse: HttpMessage,
    val dateTime: String,
    val host: String,
    val url: String,
    val types: Set<String>,
    val parameter: String,
    val method: String,
    val statusCode: Int,
    val title: String,
    val length: Int,
    val mimeType: String,
    val protocol: String,
    var comments: String = "",
    val highlighter: HuntHighlight
)


