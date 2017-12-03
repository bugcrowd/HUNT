from burp import IMessageEditorController

class MessageController(IMessageEditorController):
    def __init__(self, request_response):
        self._http_service = request_response.getHttpService()
        self._request = request_response.getRequest()
        self._response = request_response.getResponse()

    def getHttpService(self):
        return self._http_service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

