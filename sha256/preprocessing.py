from bitstring import BitArray

def bin_64bit(dec):
    return str(format(dec,'064b'))

def n_zeros(dec):
	if not dec:
		return ''
	return str(format(0, '0' + str(dec) + 'b'))

def module_solve(x):
	x %= 512
	if x < 448:
		return 448 - x
	if x > 448:
		return 960 - x
	return x

def Pre_processing(byte):
	byte = BitArray(bytes=byte).bin
	length = len(byte)
	byte += '1'
	byte = byte + n_zeros(module_solve(length+1))
	byte += bin_64bit(length)
	return byte

def cut(obj, n=512):
	return [obj[_:_ + n] for _ in range(0, len(obj), n)]