from request_parser.http.request import HttpRequest
from request_generator.request_generator import RequestGenerator

from requestparsergenerator.api import ParserBuilderType

class ParserBuilder(ParserBuilderType):
    """
    Single class that ties request_parser and request_builder.
    """

    def __init__(self, requests=[], protocol_list=[]):
        self.requests = []
        index = 0
        for request_stream in requests:
            http_request = HttpRequest(request_stream=request_stream)
            #parse the request
            http_request.parse_request_header()
            if http_request.get_scheme() == 'UNKNOWN':
                http_request.set_scheme(protocol_list[index])
            http_request.parse_request_body()
            self.requests.append(http_request)
            index += 1
    
    def generate(self, type=None, target_type=None, auto_submit=None):
        type_ = type        
        return RequestGenerator.generate_request(requests=self.requests, type=type_, target_type=target_type, auto_submit=auto_submit)