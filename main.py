#!/usr/bin/env/python
# -*- coding=utf-8 -*-

'''
	Uso:
		# python3 main.py [private-ip] [dport]

		- [private-ip]: Endereço IP privado do Manager.
		- [dport]: Porta utilizada para acessar o roteador de borda pela rede externa.


			PACKET IN
			    |
			PREROUTING--[routing]-->--FORWARD-->--POSTROUTING-->--OUT
			 - nat (dst)   |           - filter      - nat (src)
			               |                            |
			               |                            |
			              INPUT                       OUTPUT
			              - filter                    - nat (dst)
			               |                          - filter
			               |                            |
			               `----->-----[app]----->------'
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
								in_interface="eth1",
								out_interface="eth0",
								target="ACCEPT")

	# Descartar pacotes inválidos
	drop_invalid_packets = Rule(description="DROP_INVALID_PACKETS",
								module="conntrack",
								ctstates=["INVALID"],
								target="DROP")


	filter_table.append_rule(internal_to_external, "FORWARD")

	# filter_table.append_rule(drop_invalid_packets, "INPUT")
	# filter_table.append_rule(drop_invalid_packets, "OUTPUT")
	# filter_table.append_rule(drop_invalid_packets, "FORWARD")


	# Regras SSH
	ssh_on_firewall_incoming = Rule(description="Aceita novas ou já estabelecidas conexões SSH na porta [dport].", 
									protocol="tcp",
									dport=dport,
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")

	ssh_on_firewall_outgoing = Rule(description="SSH_ON_FIREWALL_OUTGOING",
									protocol="tcp",
									sport=dport,
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")

	ssh_external_to_internal_incoming = Rule(description="SSH_EXTERNAL_TO_INTERNAL_INCOMING",
  									protocol="tcp",
									dport="22",
									in_interface="eth0",
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")

	ssh_external_to_internal_outgoing = Rule(description="SSH_EXTERNAL_TO_INTERNAL_OUTGOING",
									protocol="tcp",
									sport="22",
									in_interface="eth1",
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")


	# Aplicação das regras para SSH
	filter_table.append_rule(ssh_on_firewall_incoming, "INPUT")
	filter_table.append_rule(ssh_on_firewall_outgoing, "OUTPUT")
	filter_table.append_rule(ssh_external_to_internal_incoming, "FORWARD")
	filter_table.append_rule(ssh_external_to_internal_outgoing, "FORWARD")


	# Regras para HTTP

	http_external_to_internal_incoming = Rule(description="HTTP_EXTERNAL_TO_INTERNAL_INCOMING",
									in_interface="eth0",
									protocol="tcp",
									dport="80",
									module="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	http_external_to_internal_outgoing = Rule(description="HTTP_EXTERNAL_TO_INTERNAL_OUTGOING",
									in_interface="eth1",
									protocol="tcp",
									sport="80",
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")

	http_internal_to_external_outgoing = Rule(description="HTTP_INTERNAL_TO_EXTERNAL_OUTGOING",
									in_interface="eth1",
									protocol="tcp",
									dport="80",
									module="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	http_internal_to_external_incoming = Rule(description="HTTP_INTERNAL_TO_EXTERNAL_INGOMING",
									in_interface="eth0",
									protocol="tcp",
									sport="80",
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")


	# Regras para HTTPS
	https_external_to_internal_incoming = Rule(description="HTTPS_EXTERNAL_TO_INTERNAL_INCOMING",
									in_interface="eth0",
									protocol="tcp",
									dport="443",
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")

	https_external_to_internal_outgoing = Rule(description="HTTPS_EXTERNAL_TO_INTERNAL_OUTGOING",
									in_interface="eth1",
									protocol="tcp",
									sport="443",
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")

	https_internal_to_external_outgoing = Rule(description="HTTPS_INTERNAL_TO_EXTERNAL_OUTGOING",
									in_interface="eth1",
									protocol="tcp",
									dport="443",
									module="conntrack",
									ctstates=["NEW", "ESTABLISHED"],
									target="ACCEPT")


	https_internal_to_external_incoming = Rule(description="HTTPS_INTERNAL_TO_EXTERNAL_INCOMING",
									in_interface="eth0",
									protocol="tcp",
									sport="443",
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")

	# Aplicação das regras para HTTP e HTTPS

	filter_table.append_rule(http_external_to_internal_incoming, "FORWARD")
	filter_table.append_rule(http_internal_to_external_incoming, "FORWARD")
	filter_table.append_rule(http_internal_to_external_outgoing, "FORWARD")
	filter_table.append_rule(http_external_to_internal_outgoing, "FORWARD")


	filter_table.append_rule(https_external_to_internal_incoming, "FORWARD")
	filter_table.append_rule(https_internal_to_external_incoming, "FORWARD")
	filter_table.append_rule(https_internal_to_external_outgoing, "FORWARD")
	filter_table.append_rule(https_external_to_internal_outgoing, "FORWARD")


	# Regras para SMTP
	smtp_external_to_internal_incoming = Rule(description="SMTP_EXTERNAL_TO_INTERNAL_INCOMING", 
									in_interface="eth0",
									protocol="tcp",
									dport="25",
									module="conntrack",
									ctstates=["NEW","ESTABLISHED"],
									target="ACCEPT")

	smtp_external_to_internal_outgoing = Rule(description="SMTP_EXTERNAL_TO_INTERNAL_OUTGOING",
									in_interface="eth1",
									protocol="tcp",
									sport="25",
									module="conntrack",
									ctstates=["ESTABLISHED", "RELATED"],
									target="ACCEPT")

	smtp_internal_to_external_outgoing = Rule(description="SMTP_INTERNAL_TO_EXTERNAL_OUTGOING",
								in_interface="eth1",
								protocol="tcp",
								dport="25",
								module="conntrack",
								ctstates=["NEW","ESTABLISHED"],
								target="ACCEPT")

	smtp_internal_to_external_incoming = Rule(description="SMTP_INTERNAL_TO_EXTERNAL_INCOMING",
								in_interface="eth0",
								protocol="tcp",
								sport="25",
								module="conntrack",
								ctstates=["ESTABLISHED", "RELATED"],
								target="ACCEPT")


	filter_table.append_rule(smtp_external_to_internal_incoming, "FORWARD")
	filter_table.append_rule(smtp_external_to_internal_outgoing, "FORWARD")
	filter_table.append_rule(smtp_internal_to_external_incoming, "FORWARD")
	filter_table.append_rule(smtp_internal_to_external_outgoing, "FORWARD")


	# Regra padrão para a tabela Filter
	input_policy = Rule(description="FILTER_INPUT_POLICY",  # Muito cuidado aqui! ! !
						target="DROP")

	# filter_table.set_policy(input_policy, "INPUT")
	# filter_table.set_policy(input_policy, "FORWARD")
	# filter_table.set_policy(input_policy, "OUTPUT")

	# Tabela NAT
	nat_table = Table("nat")

	# Regras NAT
	# MASQUERADE
	masquerade_rule = Rule(description="MAQUERADE_RULE",
							out_interface="eth0",
							target="MASQUERADE")

	# DNAT	 
	dnat_rule_ssh = Rule(description="DNAT_RULE_SSH",
						in_interface="eth0",
						protocol="tcp",
						dport=dport, 
						target="DNAT",
						to=private_ip+":22")

	dnat_rule_http = Rule(description="DNAT_RULE_HTTP",
						in_interface="eth0",
						protocol="tcp",
						dport="80", 
						target="DNAT",
						to=private_ip+":80")

	dnat_rule_https = Rule(description="DNAT_RULE_HTTPS",
						in_interface="eth0",
						protocol="tcp",
						dport="443", 
						target="DNAT",
						to=private_ip+":443")

	dnat_rule_smtp = Rule(description="DNAT_RULE_HTTP",
						in_interface="eth0",
						protocol="tcp",
						dport="25", 
						target="DNAT",
						to=private_ip+":25")

	# nat_table.append_rule(masquerade_rule, "POSTROUTING")
	# nat_table.append_rule(dnat_rule_ssh, "PREROUTING")
	# nat_table.append_rule(dnat_rule_http, "PREROUTING")
	# nat_table.append_rule(dnat_rule_https, "PREROUTING")
	# nat_table.append_rule(dnat_rule_smtp, "PREROUTING")

if __name__ == '__main__':
	main()
