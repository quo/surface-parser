import struct

class PrimitiveMeta(type):
	def __init__(self, clsname, bases, attrs):
		if self.s: self.struct = struct.Struct('<'+self.s)
class Primitive(metaclass=PrimitiveMeta):
	s = None
	def __class_getitem__(cls, n):
		return cls, n
class u8(Primitive): s = 'B'
class i8(Primitive): s = 'b'
class u16(Primitive): s = 'H'
class i16(Primitive): s = 'h'
class u32(Primitive): s = 'I'
class u64(Primitive): s = 'Q'
class i32(Primitive): s = 'i'
class f32(Primitive): s = 'f'

class ParseError(Exception): pass

class Block:
	def __init__(self, parent, size):
		if isinstance(parent, Block):
			self.f = parent.f
			if size > parent.remaining(): raise ParseError('cannot read %i bytes at %i, block at %i + %i' % (size, parent.f.tell(), parent.start, parent.size))
		else:
			self.f = parent
		self.size = size
	def __enter__(self):
		self.start = self.f.tell()
		self.end = self.start + self.size
		return self
	def __exit__(self, exc_type, exc_val, traceback):
		if exc_type: return
		r = self.remaining()
		if r: raise ParseError('%i unparsed bytes at %i, block at %i + %i' % (r, self.f.tell(), self.start, self.size))
	def remaining(self):
		return self.end - self.f.tell()
	def read(self, n):
		if n > self.remaining(): raise ParseError('cannot read %i bytes at %i, block at %i + %i' % (n, self.f.tell(), self.start, self.size))
		return self.f.read(n)

class StructMeta(type):
	def __init__(cls, clsname, bases, attrs):
		i = 0
		fields = []
		for tp, name in cls.fields:
			tp, n = tp if isinstance(tp, tuple) else (tp, 1)
			if not name: name = 'unknown' + str(i)
			fields.append((tp, n, name))
			i += n * tp.struct.size
		cls.fields = fields
		cls.fieldnames = frozenset(nm for tp,n,nm in fields)
		cls.struct = struct.Struct('<' + ''.join('%i%c' % (n,tp.s) for tp,n,nm in fields))
		assert cls.struct.size == i
		cls.fields_size = cls.struct.size
class Struct(metaclass=StructMeta):
	fields = []
	def read(self, b):
		#print('Reading', self.__class__.__name__)
		d = b.read(self.struct.size)
		if len(d) < self.struct.size: raise EOFError()
		d = self.struct.unpack(d)
		i = 0
		for tp, n, name in self.fields:
			x = d[i] if n == 1 else d[i:i+n]
			setattr(self, name, x)
			i += n
	
class UnhandledData:
	def __repr__(self):
		return ' '.join('%02x' % b for b in self.data)
	def read(self, b):
		self.data = b.read(b.remaining())

class List(list):
	def __init__(self, t, n=None):
		self.type = t
		self.n = n
	def read_item(self, b):
		x = self.type()
		self.append(x)
		x.read(b)
	def read(self, b):
		if isinstance(self.type, PrimitiveMeta):
			d = b.read(b.remaining() if self.n is None else self.type.struct.size * self.n)
			self.extend(struct.unpack('<%i%c' % (len(d) // self.type.struct.size, self.type.s), d))
		elif self.n is None:
			while b.remaining(): self.read_item(b)
		else:
			for _ in range(self.n): self.read_item(b)

