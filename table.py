import subprocess

class Table(object):
	"""docstring for Table"""
	def __init__(self, name):
		self.name = name

	# Adiciona uma nova regra no final da tabela
	def append_rule(self, rule, chain):
		args = self.mont_arg_list(rule, chain, "-A")
		subprocess.call(args)	

	# Exclui uma regra da tabela
	def delete_rule(self, rule, chain):
		args = self.mont_arg_list(rule, chain, "-D")
		subprocess.call(args)

	# Define a regra padrao da tabela em um determinada corrente
	def set_policy(self, rule, chain):
		args = ["iptables", "-P", chain]
		args.append(rule.target)
		subprocess.call(args)	

	# Insere uma regra em uma linha (numero) especifica da tabela
	def insert_rule(self, rule, number):
		pass

	# Zera uma regra do Firewall
	def flush_rule(self, rule):
		pass

	def mont_arg_list(self, rule, chain, met):
		args = ["iptables", met, chain]

		if rule.in_interface is not None:
			args.append("-i")
			args.append(rule.in_interface)

		if rule.out_interface is not None:
			args.append("-o")
			args.append(rule.out_interface)

		if rule.protocol is not None:
			args.append("-p")
			args.append(rule.protocol)

		if rule.dport is not None:
			args.append("--dport")
			args.append(rule.dport)

		if rule.sport is not None:
			args.append("--sport")
			args.append(rule.sport)

		if rule.source is not None:
			args.append("-s")
			args.append(rule.source)

		if rule.destination is not None:
			args.append("-d")
			args.append(rule.destination)

		if rule.match is not None:
			args.append("-m")
			args.append(rule.match)

		if rule.ctstates is not None:
			args.append("--ctstate")
			args.append(",".join(rule.ctstates))

		if rule.target is not None:
			args.append("-j")
			args.append(rule.target)

		return args