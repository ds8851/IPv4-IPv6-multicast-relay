from scapy.all import *

import pcap
conf.use_pcap=True
import pcappy as pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

#tempo de expiracao de pacote RS
timestamp=180
packets=[] #tabela com os dados dos RS
packets.append(Pacote(e8:9a:8f:78:9f:35, 625, timestamp))

#tabela que guarda enderecos MAC de origem dos RS, vlan e tempo de expiracao
class Pacote():
	def __init__(self, src, vlan, val_time):
		self.src=src
		self.vlan=vlan
		self.val_time=time.time()+val_time

#funcao apos recepcao de um pacote RA ou RS
#verifica o tipo de pacote, se for RS guarda na tabela
#se for RA envia para todos os que pediram RS na vlan
def pkt_callback(pkt):
	toRemove=[]
	if ICMPv6ND_RS in pkt:
		pkt.show()
		put_in_table(pkt)
	else:
		if ICMPv6ND_RA in pkt:
			pkt.show()
			for i in range(len(packets)):
				if packets[i].val_time < time.time():
					toRemove.append(i)
				else:
					if pkt.vlan==packets[i].vlan:
						pkt.dst=packets[i].src #coloca MAC da maquina que fez pedido RS no MAC destino do pacote
						sendp(pkt, iface='enp1s0') #envia o pacote
						#toRemove.append(i)
						hexdump(pkt)
		#remover da tabela os pedidos expirados ou atendidos
		for i in range(len(toRemove)):
			packets.pop(toRemove[i])

#coloca dados do pedido RS na tabela				
def put_in_table(pkt):
	packets.append(Pacote(pkt.src, pkt.vlan, timestamp))
	
def print_table(pkts):
	for i in range(len(pkts)):
		print('MAC: ', pkts[i].src)
		print('Vlan: ', pkts[i].vlan)
		print('Time to expire: ', pkts[i].val_time-time.time())

sniff(iface='enp1s0', filter="(ip6 and ether src e8:9a:8f:78:9f:35 and dst ff02::2) or (ip6 and dst ff02::1)", prn=pkt_callback, store=0)
print_table(packets)
