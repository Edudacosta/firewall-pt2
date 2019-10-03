class Rule(object):
	"""docstring for Rule"""
	def __init__(self, number=None, name=None, protocol=None, sports=[], dports=[], in_interfaces=[], 
					out_interfaces=[], sources=[], destinations=[], match=None, target, states=None):
		self.number = number
		self.name = name
		self.protocol = protocol
		self.sports = sports
		self.dports = dports
		self.in_interfaces = in_interfaces
		self.out_interfaces = out_interfaces
		self.sources = sources
		self.destinations = destinations
		self.match = match
		self.target = target
