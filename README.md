import os

def block_ip(ip):
    command = f"iptables -A INPUT -s {ip} -j DROP"
    os.system(command)

# Example usage
block_ip("192.168.0.10")

from flask import Flask
from flask_limiter import Limiter

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/example")
@limiter.limit("10/minute")
def example():
    return "This resource is limited to 10 requests per minute."

# Example middleware for non-Flask applications
def rate_limiting_middleware(get_response):
    def middleware(request):
        # Add your rate-limiting logic here
        # ...
        response = get_response(request)
        return response
    return middleware

    from scapy.all import *

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet.getlayer(TCP).flags == 0x12:  # SYN flag is set
        src_ip = packet[IP].src
        if detect_syn_flood.packets_per_second[src_ip] > 100:
            detect_syn_flood.packets_per_second[src_ip] += 1
            print(f"Potential Syn Flood Attack from {src_ip}")
        else:
            detect_syn_flood.packets_per_second[src_ip] = 1

def start_ids():
    detect_syn_flood.packets_per_second = {}
    sniff(prn=detect_syn_flood, filter="tcp port 80", store=0)

# Example usage
start_ids(
