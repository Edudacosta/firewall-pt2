class Rule(object):
	"""docstring for Rule"""
	def __init__(self, number=None, description=None, protocol=None, sport=None, dport=None, in_interface=None, 
					out_interface=None, source=None, destination=None, module=None, target=None, to=None, ctstates=[]):
		self.number = number
		self.description = description
		self.protocol = protocol
		self.sport = sport
		self.dport = dport
		self.in_interface = in_interface
		self.out_interface = out_interface
		self.source = source
		self.destination = destination
		self.module = module
		self.target = target
		self.ctstates = ctstates
		self.to = to
