#!/usr/bin/env/python
# -*- coding=utf-8 -*-

'''
	Uso:
		# python3 main.py [private-ip] [dport]

		- [private-ip]: Endereço IP privado do Manager.
		- [dport]: Porta utilizada para acessar o roteador de borda pela rede externa.

'''

import subprocess
import sys

from table import Table
from rule import Rule

def main():

	if len(sys.argv) < 3:
		print(__doc__)
		sys.exit(1)

	private_ip = sys.argv[1]
	dport = sys.argv[2]

	# Tabela Filter
	filter_table = Table("filter")

	# Regra para acesso à rede externa
	internal_to_external = Rule(description="INTERNAL_TO_EXTERNAL",
								in_interface="eth0",
								out_interface="eth1",
								target="ACCEPT")

	# Descartar pacotes inválidos
	drop_invalid_packets = Rule(description="DROP_INVALID_PACKETS",
								module="conntrack",
								ctstates=["INVALID"],
								target="DROP")


	# filter_table.append_rule(internal_to_external, "FORWARD")

	# filter_table.append_rule(drop_invalid_packets, "INPUT")
	# filter_table.append_rule(drop_invalid_packets, "OUTPUT")
	# filter_table.append_rule(drop_invalid_packets, "FORWARD")


	# Regras SSH
	ssh_on_firewall = Rule(description="Aceita novas ou já estabelecidas conexões SSH na porta [dport].", 
									protocol="tcp",
									dport=dport, 
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")

	ssh_internal_to_internal = Rule(description="SSH_INTERNAL_TO_INTERNAL",
  									protocol="tcp",
									dport="22",
									in_interface="eth0",
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")

	ssh_internal_to_external = Rule(description="SSH_INTERNAL_TO_EXTERNAL",
									protocol="tcp",
									sport="22",
									in_interface="eth1",
									module="conntrack",
									ctstates=["ESTABLISHED"],
									target="ACCEPT")


	# Aplicação das regras para SSH
	filter_table.append_rule(ssh_on_firewall, "INPUT")

	filter_table.append_rule(ssh_internal_to_internal, "FORWARD")

	filter_table.append_rule(ssh_internal_to_external, "FORWARD")


	# Regras para HTTP
	http_public_interface = Rule(description="HTTP_PUBLIC_INTERFACE", # Não aplicar
									# in_interface="eth0",
									protocol="tcp",
									dport=dport, # Padrão=80 e 443. Não usadas
									module="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	http_private_interface = Rule(description="HTTP_PRIVATE_INTERFACE",
									# in_interface="eth1",
									protocol="tcp",
									sport="80",
									module="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")


	https_private_interface = Rule(description="HTTPS_PUBLIC_INTERFACE",
									# in_interface="eth1",
									protocol="tcp",
									sport="443",
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")

	# Aplicação das regras para HTTP e HTTPS

	# filter_table.append_rule(http_public_interface, "INPUT") # Não aplicar!!!
	# filter_table.append_rule(http_public_interface, "FORWARD")

	# filter_table.append_rule(http_private_interface, "INPUT")
	# filter_table.append_rule(http_private_interface, "FORWARD")

	# filter_table.append_rule(https_private_interface, "INPUT")
	# filter_table.append_rule(https_private_interface, "FORWARD")

	# Regras para SMTP
	smtp_public_interface = Rule(description="SMTP_PUBLIC_INTERFACE", # Não aplicar!!!
									in_interface="eth0",
									protocol="tcp",
									dport=dport, # Padrão=25. Não usada
									module="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	smtp_private_interface = Rule(description="SMTP_PRIVATE_INTERFACE",
								in_interface="eth1",
								protocol="tcp",
								sport="25",
								module="conntrack",
								ctstates=["NEW,ESTABLISHED"],
								target="ACCEPT")

	# filter_table.append_rule(smtp_public_interface, "INPUT")
	# filter_table.append_rule(smtp_public_interface, "FORWARD")

	# filter_table.append_rule(smtp_private_interface, "INPUT")
	# filter_table.append_rule(smtp_private_interface, "FORWARD")

	# Regra padrão para a tabela Filter
	input_policy = Rule(description="FILTER_INPUT_POLICY",  # Muito cuidado aqui! ! !
						target="DROP")

	# filter_table.set_policy(input_policy, "INPUT")
	# filter_table.set_policy(input_policy, "FORWARD")

	# Tabela NAT
	nat_table = Table("nat")

	# Regras NAT
	masquerade_rule = Rule(description="MAQUERADE_RULE",
							out_interface="eth0",
							target="MASQUERADE")

	dnat_rule = Rule(description="DNAT_RULE",
						in_interface="eth0",
						protocol="tcp",
						dport=dport, 
						target="DNAT",
						to=private_ip+":22")

	# nat_table.append_rule(masquerade_rule, "POSTROUTING")
	# nat_table.append_rule(dnat_rule, "PREROUTING")

if __name__ == '__main__':
	main()
