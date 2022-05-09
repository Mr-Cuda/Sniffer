# Sniffer by Mr-Cuda
import scapy.all as scapy # this has problems with imports
from scapy.layers import http

def snif(i𝘧𝘢𝘤𝘦):
    scapy.sniff(i𝘧𝘢𝘤𝘦=i𝘧𝘢𝘤𝘦 , store=False, prn=processPacket)

def processPacket(packet):
  if packet.haslayer(http.HTTPRequest): 
      print("packet.show()".join(map(chr, packet[http.HTTPRequest].host)))
      if packet.haslayer(http.Raw):
          print("packet.show()".json(map(chr, packet[http.Raw].load)))


snif("Wi-Fi") # it's very simple
