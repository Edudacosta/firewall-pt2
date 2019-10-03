class Table(object):
	"""docstring for Table"""
	def __init__(self, name):
		self.name = name

	# Adiciona uma nova regra no final da tabela
	def append_rule(self, rule, chain):
		args = ["iptables", "-A", chain]
		# subprocess.call(args)

	# Insere uma regra em uma linha (número) específica da tabela
	def insert_rule(self, rule, number):
		pass

	# Exclui uma regra da tabela
	def delete_rule(self, rule):
		args = ["iptables", "-D", chain]

	# Define a regra padrão da tabela em um determinada corrente
	def set_policy(self, rule, chain):
		args = ["iptables", "-P", chain]

		args.append(rule.target)

		subprocess.call(args)	

	# Zera uma regra do Firewall
	def flush_rule(self, rule)
		pass