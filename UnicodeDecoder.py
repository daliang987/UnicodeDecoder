from burp import IBurpExtender, IHttpListener
import codecs
import re

class BurpExtender(IBurpExtender, IHttpListener):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Unicode Decoder")
		callbacks.registerHttpListener(self)

		callbacks.printOutput("Unicode Decoder::")
		callbacks.printOutput("Author:WangDaliang")
		callbacks.printOutput("Version: 1.0")
		callbacks.printOutput("Description: This is a Burp Suite extension that automatically decodes unicode escape sequences. It supports Persian, Chinese, Russian and other languages probably. Also works on Proxy, Repeater and Intruder Tools.")
		callbacks.printOutput("GitHub: https://github.com/daliang987/UnicodeDecoder")

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		toolName = self._callbacks.getToolName(toolFlag)
		if toolName == "Repeater" or toolName == "Proxy" or toolName == "Intruder":
			if not messageIsRequest:
				is_response_json = False

				response = messageInfo.getResponse()
				analyzedResponse = self._helpers.analyzeResponse(response)
				response_headers = analyzedResponse.getHeaders()

				for header in response_headers:
					if header.lower().startswith("content-type: application/json"):
						is_response_json = True

				if is_response_json:
					bodyBytes = response[analyzedResponse.getBodyOffset():] # array.array
					bodyStr = self._helpers.bytesToString(bodyBytes) # unicode
					u_char_escape_list=re.findall(r'(?:\\u\w{4})+',bodyStr) 
					newBodyStr=bodyStr
     
					if u_char_escape_list:
						for u_char_escape in u_char_escape_list:
							# print type(u_char_escape) # unicode
							u_char=codecs.decode(u_char_escape,'unicode_escape').encode("utf-8") # str
							newBodyStr=newBodyStr.replace(u_char_escape,u_char) # unicode

					modifiedResponse = self._helpers.buildHttpMessage(response_headers, newBodyStr)
					messageInfo.setResponse(modifiedResponse)