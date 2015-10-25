"""
This script send a copy of data to the loopback interface in port 80.
Run a dummy web server on port 80 to do the synchronisation of tcp.
By Olivier Soucy.
"""
def request(context, flow):
    newFlow = context.duplicate_flow(flow)
    newFlow.request.host = "127.0.0.1"
    newFlow.request.port = 80
    newFlow.request.scheme = "http"
    context.replay_request(newFlow)

def response(context, flow):
    newFlow = context.duplicate_flow(flow)
    newFlow.request.host = "127.0.0.1"
    newFlow.request.port = 80
    newFlow.request.scheme = "http"
    newFlow.request.content = flow.response.get_decoded_content()
    context.replay_request(newFlow)
