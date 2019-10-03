class Rule(object):
	"""docstring for Rule"""
	def __init__(self, number=None, name=None, protocol=None, sport=None, dport=None, in_interface=None, 
					out_interface=None, source=None, destination=None, match=None, target=None, ctstates=[]):
		self.number = number
		self.name = name
		self.protocol = protocol
		self.sport = sport
		self.dport = dport
		self.in_interface = in_interface
		self.out_interface = out_interface
		self.source = source
		self.destination = destination
		self.match = match
		self.target = target
		self.ctstates = ctstates
