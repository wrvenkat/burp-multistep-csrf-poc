import sys
import os

from request_parser.http.request import HttpRequest
from request_parser.conf.settings import Settings
from request_generator.request_generator import RequestGenerator

from parserbuilder.java.api import ParserBuilderType

class ParserBuilder(ParserBuilderType):
    """
    Class that ties request_parser and request_builder and serves as the entry point for Java.
    """

    def __init__(self, file_upload_path=None, requests=[], protocol_list=[]):
        self.sys_path = str(sys.path)
        self.sys_environ = str(os.environ)
        #print "Sys path is "+self.sys_path
        #print "OS environ dict:\n"+self.sys_environ

        self.requests = []
        index = 0
        settings = None
        if file_upload_path is not None:
            settings = Settings({Settings.Key.FILE_UPLOAD_DIR : file_upload_path})
        
        for request_stream in requests:
            http_request = HttpRequest(request_stream=request_stream, settings=settings)
            #parse the request
            http_request.parse_request_header()
            if http_request.get_scheme() == 'UNKNOWN':
                http_request.set_scheme(protocol_list[index])
            http_request.parse_request_body()
            self.requests.append(http_request)
            index += 1
    
    def generate(self, type=None, target_type=None, auto_submit=None):
        type_ = type
        return_value = RequestGenerator.generate_request(requests=self.requests, type=type_, target_type=target_type, auto_submit=auto_submit)

        return return_value #"SYS: "+self.sys_path+" and environ:\n"+self.sys_environ+return_value