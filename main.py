#!/usr/bin/env/python
# -*- coding=utf-8 -*-

'''
	Uso:
		# python3 main.py [private-ip] [dport]

		- [private-ip]: Endereço IP privado do roteador de borda.
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

	# Regras SSH
	ssh_public_interface = Rule(name="SSH_PUBLIC_INTERFACE",
										in_interface="eth0",
										protocol="tcp",
										dport=dport, # Padrão=22. Não usada.
										match="conntrack",
										ctstates=["NEW", "ESTABLISHED"],
										target="ACCEPT")

	ssh_private_interface = Rule(name="SSH_PRIVATE_INTERFACE",
										in_interface="eth1",
										protocol="tcp",
										sport="22",
										match="conntrack",
										ctstates=["NEW", "ESTABLISHED"],
										target="ACCEPT")

	# Aplicação das regras para SSH

	# filter_table.append_rule(ssh_public_interface, "INPUT")
	# filter_table.append_rule(ssh_public_interface, "FORWARD")

	# filter_table.append_rule(ssh_private_interface, "INPUT")
	# filter_table.append_rule(ssh_private_interface, "FORWARD")

	# Regras para HTTP
	http_public_interface = Rule(name="HTTP_PUBLIC_INTERFACE", # Não aplicar
									in_interface="eth0",
									protocol="tcp",
									dport=dport, # Padrão=80 e 443. Não usadas
									match="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	http_private_interface = Rule(name="HTTP_PRIVATE_INTERFACE",
									in_interface="eth1",
									protocol="tcp",
									dport="80",
									match="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")


	https_private_interface = Rule(name="HTTPS_PUBLIC_INTERFACE",
									in_interface="eth1",
									protocol="tcp",
									dport="443",
									match="conntrack",
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
	smtp_public_interface = Rule(name="SMTP_PUBLIC_INTERFACE", # Não aplicar!!!
									in_interface="eth0",
									protocol="tcp",
									dport=dport, # Padrão=25. Não usada
									match="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	smtp_private_interface = Rule(name="SMTP_PRIVATE_INTERFACE",
								in_interface="eth1",
								protocol="tcp",
								dport="25",
								match="conntrack",
								ctstates=["NEW,ESTABLISHED"],
								target="ACCEPT")

	# filter_table.append_rule(smtp_public_interface, "INPUT")
	# filter_table.append_rule(smtp_public_interface, "FORWARD")

	# filter_table.append_rule(smtp_private_interface, "INPUT")
	# filter_table.append_rule(smtp_private_interface, "FORWARD")

	# Regra padrão para a tabela Filter
	input_policy = Rule(name="FILTER_INPUT_POLICY",  # Muito cuidado aqui! ! !
						target="DROP")

	# filter_table.set_policy(input_policy, "INPUT")
	# filter_table.set_policy(input_policy, "FORWARD")

	# Tabela NAT
	nat_table = Table("nat")

	# Regras NAT
	masquerade_rule = Rule(name="MAQUERADE_RULE",
							out_interface="eth0",
							target="MASQUERADE")

	dnat_rule = Rule(name="DNAT_RULE",
						in_interface="eth0",
						protocol="tcp",
						dport=dport, 
						target="DNAT",
						to=private_ip+":22")

	# nat_table.append_rule(masquerade_rule, "POSTROUTING")
	# nat_table.append_rule(dnat_rule, "PREROUTING")

if __name__ == '__main__':
	main()
