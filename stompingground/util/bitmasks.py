def int_to_ascii(n):
		"""convert unsigned integer to ASCII binary representation"""
		s = ''
		while n != 0:
			if n % 2 == 0: bit = '0'
			else: bit = '1'
			s = bit + s
			n >>= 1
		s = ('0' * (32 - len(s))) + s
		return s or '0'

def int_to_ascii_inverse(n):
		"""convert unsigned integer to ASCII binary representation"""
		s = ''
		while n != 0:
			if n % 2 == 0: bit = '1'
			else: bit = '0'
			s = bit + s
			n >>= 1
		s = ('0' * (32 - len(s))) + s
		return s or '0'