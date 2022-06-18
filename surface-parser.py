#!/usr/bin/python3

import sys, math, os, stat, gzip, struct, io

from surfacedata import *


# hierarchical dump

def repr_dft_component(r, i):
	# print absolute value and phase instead of raw real/imag values
	abs = math.hypot(r, i)
	phase = math.atan2(r, i) / (2*math.pi)
	return '%5i/%02i' % (abs, phase * 100 % 100)

def repr_field(obj, name):
	val = getattr(obj, name)
	if name in ('type', 'id', 'flags'): return '0x%x' % val
	return repr(val)

def print_struct(name, val, indent):
	if name == 'data': name = None
	s = '  '*indent
	if name: s += name + ': '
	if isinstance(val, DftWindowRow):
		dft = ' '.join(repr_dft_component(r, i) for r,i in zip(val.real, val.imag))
		print(s + f'{val.frequency:10} {val.magnitude:10}{val.first:4}{val.mid:4}{val.last:4} {dft}')
	elif isinstance(val, Struct):
		print(s + type(val).__name__ + ': ' + ', '.join(nm+'='+repr_field(val, nm) for tp,n,nm in val.fields))
		for k,v in val.__dict__.items():
			if k not in val.fieldnames:
				print_struct(k, v, indent+1)
	elif isinstance(val, list):
		if len(val) == 0:
			print(s + '[]')
		elif not isinstance(val[0], Struct):
			print(s + repr(val))
		else:
			for i, x in enumerate(val):
				print_struct(name, x, indent)
	else:
		print(s + repr(val))


# dft magnitude display

class DftInfo: pass
class DftPrinter:
	def __init__(self):
		self.dfts = []
		self.info = []
		self.counter = 0
		self.last_ts = 0

	def add(self, o):
		if isinstance(o, list):
			for x in o: self.add(x)
		elif isinstance(o, PacketPenMetadata):
			if o.group_counter != self.counter:
				self.print()
				self.dfts.clear()
				self.counter = o.group_counter
		elif isinstance(o, PacketPenDftWindow):
			self.dfts.append(o)
		elif hasattr(o, 'data'):
			self.add(o.data)

	def color(self, x):
		if x is None: return "\033[0m"
		return "\033[48;2;%i;%i;%im" % (max(0,min(255,round(x*500)-100)), round(x*100), round((1-x)*100))

	def get_row_text(self, r):
		m = math.log2(max(1,r.magnitude)) / 32
		yield self.color(m)
		yield '0123456789ABCDEF'[round(m * 16)]

	def get_bits(self, dft, start, end):
		if dft is None: return None
		val = 0
		bit = 1
		for i in range(start, end, 2):
			a = dft.x[i+0].magnitude + dft.y[i+0].magnitude
			b = dft.x[i+1].magnitude + dft.y[i+1].magnitude
			if b > a*4: val |= bit
			elif not a > b*4: return None
			bit <<= 1
		return val

	def get_dft_text(self, i, d):
		yield ' '
		yield str(i.data_type)
		if d is None:
			yield ' '*(i.num_rows*2+2)
		else:
			assert i.num_rows == d.num_rows
			yield 'x'
			for r in d.x: yield from self.get_row_text(r)
			yield self.color(None)
			yield 'y'
			for r in d.y: yield from self.get_row_text(r)
			yield self.color(None)
		if i.data_type == 10:
			b = self.get_bits(d, 0, i.num_rows)
			yield '   ' if b is None else '=%02x' % b
		if i.data_type == 11:
			b = self.get_bits(d, 7, 13)
			yield ' ' if b is None else '=%x' % b

	def print(self):
		if not self.dfts: return
		ts = min(x.timestamp for x in self.dfts)
		dt = (ts - self.last_ts) & 0xffffffff
		self.last_ts = ts
		self.dfts.sort(key=lambda x: x.data_type)
		i = 0
		line = []
		for x in self.dfts:
			while i < len(self.info) and self.info[i].data_type < x.data_type:
				line.extend(self.get_dft_text(self.info[i], None))
				i += 1
			if i >= len(self.info) or self.info[i].data_type != x.data_type:
				info = DftInfo()
				info.data_type = x.data_type
				info.num_rows = x.num_rows
				self.info.insert(i, info)
			else:
				info = self.info[i]
				if x.num_rows > info.num_rows: info.num_rows = x.num_rows
			line.extend(self.get_dft_text(info, x))
			i += 1
		print('%10i%+11i' % (ts,dt) + ''.join(line))


# file formats

FmtIthc, FmtIptsBin, FmtIptsTxt = range(3)

def read_buffers(f, fmt):
	if fmt == FmtIptsTxt:
		data = None
		for line in f:
			if line.startswith(b'='):
				l = line.index(b'Buffer:') + 7
				r = line.index(b'=', l)
				bufnum = int(line[l:r])
				l = line.index(b'Type:') + 5
				r = line.index(b'=', l)
				tp = int(line[l:r])
				l = line.index(b'Size:') + 5
				r = line.index(b'=', l)
				sz = int(line[l:r])
				data = []
			elif data is not None:
				data.extend(int(x, 16) for x in line.split())
				if len(data) >= sz:
					buf = struct.pack('<III52x', tp, sz, bufnum) + bytes(data)
					with Block(io.BytesIO(buf), len(buf)) as b:
						x = IptsData()
						x.read(b)
						yield x
					data = None
		return
	while True:
		start = f.tell()
		try:
			if fmt == FmtIthc:
				x = IthcApi()
				x.read(f)
				yield x.data
			elif fmt == FmtIptsBin:
				x = IptsData()
				x.read(f)
				yield x
		except EOFError:
			if f.tell() == start: break
			raise


def main(args):
	dft = False
	fmt = None
	for a in args:
		if not a.startswith('-'): continue
		if a == '--dft': dft = True
		elif a == '--ithc': fmt = FmtIthc
		elif a == '--iptsbin': fmt = FmtIptsBin
		elif a == '--iptstxt': fmt = FmtIptsTxt
		else: raise Exception(a)
	if fmt is None:
		raise Exception('No format specified')
	for fn in args:
		if fn.startswith('-'): continue
		if fn.endswith('.gz'): f = gzip.open(fn, 'rb')
		else: f = open(fn, 'rb', buffering=0x10000)
		with f:
			dftprinter = DftPrinter()
			for x in read_buffers(f, fmt):
				if dft:
					dftprinter.add(x)
				else:
					print_struct(None, x, 0)

if __name__ == '__main__':
	main(sys.argv[1:])

