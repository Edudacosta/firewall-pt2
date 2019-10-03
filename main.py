#!/usr/bin/env/python
# -*- coding=utf-8 -*-

import subprocess

from rule import Rule

def main():
	# Tabela Filter
	input_chain = Chain("INPUT")
	output_chain = Chain("OUTPUT")
	forward_chain = Chain("FORWARD")

	# Tabela Nat
	postrouting_chain = Chain("POSTROUTING")

	# Regras para SSH
	ssh_input_rule = Rule(name="SSH_INPUT_RULE", 
						protocol="tcp",
						dports=["13508", "22"],
						# match="conntrack",				# Adicionar regras match de conexão depois (Causa do erro)
						# states=["NEW", "ESTABLISHED"],
						target="ACCEPT")

	ssh_output_rule = Rule(name="SSH_OUTPUT_RULE",
						protocol="tcp",
						dports=["13508", "22"],
						# match="conntrack",		
						# states=["ESTABLISHED"],
						target="ACCEPT")

	input_chain.append_rule(ssh_input_rule)
	output_chain.append_rule(ssh_output_rule)

	# input_chain.delete_rule(ssh_input_rule)
	# output_chain.delete_rule(ssh_output_rule)

	# Regras para HTTP e HTTPS
	http_input_rule = Rule(name="HTTP_INPUT_RULE",
						protocol="tcp",
						dports=["80", "443"],
						match="conntrack",
						states=["NEW","ESTABLISHED"],
						target="ACCEPT")

	http_output_rule = Rule(name="HTTP_OUTPUT_RULE",
						protocol="tcp",
						dports=["80", "443"],
						match="conntrack",
						states=["ESTABLISHED"],
						target="ACCEPT")

	# input_chain.append_rule(http_input_rule)
	# output_chain.append_rule(http_output_rule)


	# Regras para SMTP
	smtp_input_rule = Rule(name="SMTP_INPUT_RULE",
						protocol="tcp",
						dports=["25"],
						match="conntrack",
						states=["NEW","ESTABLISHED"],
						target="ACCEPT")

	smtp_output_rule = Rule(name="SMTP_OUTPUT_RULE",
						protocol="tcp",
						dports=["25"],
						match="conntrack",
						states=["NEW,ESTABLISHED"],
						target="ACCEPT")

	# input_chain.append_rule(smtp_input_rule)
	# output_chain.append_rule(smtp_output_rule)


	# Regra padrão
	policy_input_rule = Rule(name="POLICY_INPUT_RULE",
							target="ACCEPT")

	# input_chain.set_policy(policy_input_rule)
	# output_chain.set_policy(policy_input_rule)


if __name__ == '__main__':
	main()
