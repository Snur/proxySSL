"""
This script decrypt https and transfer it to port 8081.
By Olivier Soucy.
"""
def request(context, flow):
    flow.request.port = 8081
    flow.request.scheme = "http"
