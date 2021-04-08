package org.zaproxy.zap.extension.hunt

import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.view.View
import org.zaproxy.zap.extension.search.SearchMatch
import java.net.URLDecoder

class HuntHighlight(
    private val reqRes: HttpMessage,
    private val tokens: String
) {

    private val searchMatch: Pair<SearchMatch?, SearchMatch?> by lazy {
        Pair(
            searchMatcher(tokens, SearchMatch.Location.REQUEST_HEAD),
            searchMatcher(tokens, SearchMatch.Location.REQUEST_BODY)
        )
    }

    fun highlight() {
        if (searchMatch.first != null) {
            View.getSingleton().requestPanel.highlightHeader(searchMatch.first)
        } else if (searchMatch.second != null) {
            View.getSingleton().requestPanel.highlightBody(searchMatch.second)
        }
    }

    private fun searchMatcher(token: String, searchLocation: SearchMatch.Location): SearchMatch? {
        val pattern = token.toRegex()
        var match = if (searchLocation == SearchMatch.Location.REQUEST_HEAD) {
            pattern.find(reqRes.requestHeader.toString())
        } else {
            pattern.find(reqRes.requestBody.toString())
        }

        if (match == null) {
            val decodedPattern = URLDecoder.decode(token, "UTF-8").toRegex()
            match = if (searchLocation == SearchMatch.Location.REQUEST_HEAD) {
                decodedPattern.find(reqRes.requestHeader.toString())
            } else {
                decodedPattern.find(reqRes.requestBody.toString())
            }
        }


        return match?.let { matchResult ->
            SearchMatch(
                reqRes,
                searchLocation,
                matchResult.range.first,
                matchResult.range.last + 1
            )
        }
    }
}