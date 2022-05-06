# Sniffer by Mr-Cuda
import scapy.all as scapy
from scapy.layers import http

def sniff(i𝘧𝘢𝘤𝘦):
    scapy.sniff(i𝘧𝘢𝘤𝘦=i𝘧𝘢𝘤𝘦 , store=False, prn=processPacket)

def processPacket(packet):
  if packet.haslayer(http.HTTPRequest): 
      print("".join(map(chr, packet[http.HTTPRequest].host)))
      if packet.haslayer(http.Raw):
          print("".json(map(chr, packet[http.Raw].load)))


sniff("Wi-Fi") # it's very simple
