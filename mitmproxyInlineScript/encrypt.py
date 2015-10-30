"""
This script encrypt http and transfer it to port 443.
By Olivier Soucy.
"""
def request(context, flow):
    flow.request.port = 443 
    flow.request.scheme = "https"
