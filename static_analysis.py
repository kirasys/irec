import r2pipe

class FunctionAnalysis:
	def __init__(self, path):
		self.r = r2pipe.open(path)

	def prototype(self, func_addr):
		self.r.cmd('s 0x%x' % func_addr)
		self.r.cmd('af')
		result = reversed(self.r.cmd('afv').strip().split('\n'))

		prototypes = []
		for line in result:
			if line.find('arg') >= 0:
				prototypes.append(line.split('@')[-1].strip())
			else:
				break

		return prototypes


