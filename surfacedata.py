from bindata import *

class IthcApi(Struct):
	fields = [
	(u8, 'hdr_size'),
	(u8[3], 'reserved'),
	(u32, 'msg_num'),
	(u32, 'size'),
	]

	def read(self, b):
		Struct.read(self, b)
		b.read(self.hdr_size - self.fields_size)
		with Block(b, self.size) as b:
			self.data = IptsData()
			self.data.read(b)

class IptsDumpHidHeader(Struct):
	fields = [
	(u16, 'vendor'),
	(u16, 'product'),
	(u32, 'padding'),
	(u64, 'buffer_size'),
	(u8, 'has_meta'),
	]

	def read(self, b):
		Struct.read(self, b)
		if self.has_meta:
			with Block(b, 105) as b:
				# this is a dump of an iptsd struct, the format does not match the Metadata struct below
				self.meta = UnhandledData()
				self.meta.read(b)

class IptsDumpHidData(Struct):
	fields = [
	(u64, 'size'),
	]

	def read(self, b, buffer_size):
		Struct.read(self, b)
		with Block(b, buffer_size) as b:
			with Block(b, self.size) as d:
				self.data = HidReportInput()
				self.data.read(d)
			b.read(b.remaining()) # junk

class IptsData(Struct):
	fields = [
	(u32, 'type'),
	(u32, 'size'),
	(u32, 'buffer'),
	(u32[13], ''),
	]

	def read(self, b):
		Struct.read(self, b)
		if hasattr(b, 'remaining') and self.size > b.remaining():
			self.truncated = UnhandledData()
			self.truncated.read(b)
		else:
			with Block(b, self.size) as b:
				if self.type == 0: self.data = IptsPayload()
				elif self.type == 3: self.data = HidReportInput()
				elif self.type == 4: self.data = HidReportFeature()
				elif self.type == 5: self.data = HidReportDescriptor()
				else: self.data = UnhandledData()
				self.data.read(b)

class IptsPayload(Struct):
	fields = [
	(u32, 'counter'),
	(u32, 'frames'),
	(u32, ''),
	]

	def read(self, b):
		Struct.read(self, b)
		self.data = []
		for _ in range(self.frames):
			f = IptsFrame()
			self.data.append(f)
			f.read(b)

class IptsFrame(Struct):
	fields = [
	(u16, 'index'),
	(u16, 'type'),
	(u32, 'size'),
	(u32[2], ''),
	]
	
	def read(self, b):
		Struct.read(self, b)
		with Block(b, self.size) as b:
			if self.type in (6,7,8): self.data = List(Packet)
			# type 10 = 1 data byte?
			else: self.data = UnhandledData()
			self.data.read(b)

class HidReportInput(Struct):
	fields = [
	(u8, 'id'),
	]

	def read(self, b):
		Struct.read(self, b)
		if self.id == 0: return
		elif self.id == 0x40: self.data = HidReportSingletouch()
		elif self.id in [7,8,10,11,12,13,26,28]: self.data = HidReportContainer()
		else: raise ParseError('unknown report id %i at %i' % (self.id, b.f.tell()))
		self.data.read(b)

class HidReportFeature(Struct):
	fields = [
	(u8, 'id'),
	]

	def read(self, b):
		Struct.read(self, b)
		if self.id == 5: self.data = HidFeatureMultitouch()
		elif self.id == 6: self.data = HidFeatureMetadata()
		else: raise ParseError('unknown report id %i at %i' % (self.id, b.f.tell()))
		self.data.read(b)

class HidReportDescriptor(Struct):
	fields = [
	(u32[2], ''),
	]

	def read(self, b):
		Struct.read(self, b)
		self.data = b.read(b.remaining())

class HidFeatureMultitouch(Struct):
	fields = [
	(u8, 'enabled'),
	]

class HidFeatureMetadata(Struct):
	fields = []
	def read(self, b):
		Struct.read(self, b)
		self.data = Container()
		self.data.read(b)

class Metadata(Struct):
	fields = [
	(u32, 'rows'),
	(u32, 'cols'),
	(u32, 'screen_width'), # mm*100
	(u32, 'screen_height'), # mm*100
	(u8, ''),
	# transform matrix to use for converting row/col to physical screen coords
	(f32, 'xx'), (f32, 'yx'), (f32, 'tx'),
	(f32, 'xy'), (f32, 'yy'), (f32, 'ty'),
	# unknown floats, possibly tilt transform?
	(f32[16], '')
	]

class HidReportSingletouch(Struct):
	fields = [
	(u8, 'button'),
	(u16, 'x'),
	(u16, 'y'),
	]

class HidReportContainer(Struct):
	fields = [
	(u16, 'timestamp'),
	]

	def read(self, b):
		Struct.read(self, b)
		self.data = Container()
		self.data.read(b)
		b.read(b.remaining()) # junk

class Container(Struct):
	fields = [
	(u32, 'size'),
	(u8, 'zero'), # always zero
	(u8, 'type'),
	(u8, ''), # 1 for heatmap container, 0 for root and packets
	]

	def read(self, b):
		Struct.read(self, b)
		fixup = 4 if self.type == 0xff and self.size == 11 else 0 # XXX hack for SP7 packet 0x74
		with Block(b, self.size - self.fields_size + fixup) as b:
			if self.type == 0: self.data = List(Container)
			elif self.type == 1: self.data = Heatmap()
			elif self.type == 2: self.data = Metadata()
			elif self.type == 0xff: self.data = List(Packet)
			else: raise ParseError('unknown container type %i at %i' % (self.type, b.f.tell()))
			self.data.read(b)

class Packet(Struct):
	fields = [
	(u8, 'type'),
	(u8, 'flags'),
	(u16, 'size'),
	]

	def read(self, b):
		Struct.read(self, b)
		with Block(b, self.size) as b:
			if self.type == 0: self.data = PacketStart()
			# 0x02 ? 0x 00 00 00 xx xx 00 00
			elif self.type == 0x03: self.data = PacketHeatmapDimensions()
			elif self.type == 0x04: self.data = PacketFrequencyNoise()
			# 0x06 ? 00 00 00 00
			# 0x07 ? 00 0x 00 00
			elif self.type == 0x10: self.data = PacketStylusSimple()
			# 0x12 ? nn 00 00 00 { u32, u32, u8[12]? }[n]
			elif self.type == 0x25:
				self.data = HeatmapData(b.read(b.remaining()))
				return
			# 0x32 ? xx xx 00 00 nn xx[n] 5E
			# 0x33 ? 0x xx 00 00 xx xx 0x xx xx xx 0x xx 00 00 00 00 00 00 00 00 00 00 00 00
			# 0x51 ? 00 00 nn 00 0x 00 00 00 { mm 64 0x 00 xx xx xx xx, u32[m] }[n]
			# 0x56 ? xx xx 0x xx + packet 0x51 data
			elif self.type == 0x57: self.data = PacketPenGeneral()
			# 0x58 PenJnrOutput
			elif self.type == 0x59: self.data = PacketPenNoiseMetricsOutput()
			elif self.type == 0x5a: self.data = PacketPenDataSelection()
			elif self.type == 0x5b: self.data = PacketPenMagnitude()
			elif self.type == 0x5c: self.data = PacketPenDftWindow()
			# 0x5d PenMultipleRegion
			elif self.type == 0x5e: self.data = PacketPenTouchedAntennas()
			elif self.type == 0x5f: self.data = PacketPenMetadata()
			elif self.type == 0x60: self.data = PacketStylusTiltSerial()
			elif self.type == 0x61: self.data = PacketStylusTilt()
			elif self.type == 0x62: self.data = PacketPenDetection()
			elif self.type == 0x63: self.data = PacketPenLift()
			# 0x74 ? 00 00 00 00 (SP7)
			elif self.type == 0xff: self.data = PacketEnd()
			#else: raise ParseError('unknown packet type %i at %i' % (self.type, b.f.tell()))
			else: self.data = UnhandledData()
			self.data.read(b)

class PacketStart(Struct):
	fields = [
	(u8[2], ''),
	(u16, 'seq_num'),
	(u32, 'timestamp'),
	]

class PacketEnd(Struct):
	fields = [
	(u16, 'seq_num'),
	(u16, 'num_packets'),
	]

class PacketStylusSimple(Struct):
	fields = [
	(u8, 'num_data'),
	(u8[3], ''),
	(u32, 'serial'),
	]

	def read(self, d):
		Struct.read(self, d)
		self.data = List(StylusDataSimple, self.num_data)
		self.data.read(d)

class PacketStylusTiltSerial(Struct):
	fields = [
	(u8, 'num_data'),
	(u8[3], ''),
	(u32, 'serial'),
	]

	def read(self, d):
		Struct.read(self, d)
		self.data = List(StylusDataTilt, self.num_data)
		self.data.read(d)

class PacketStylusTilt(Struct):
	fields = [
	(u8, 'num_data'),
	(u8[3], ''),
	]

	def read(self, d):
		Struct.read(self, d)
		self.data = List(StylusDataTilt, self.num_data)
		self.data.read(d)

class StylusDataSimple(Struct):
	fields = [
	(u8[4], ''),
	(u8, 'mode'),
	(u16, 'x'),
	(u16, 'y'),
	(u16, 'pressure'),
	(u8, ''),
	]

class StylusDataTilt(Struct):
	fields = [
	(u16, 'timestamp'),
	(u16, 'mode'),
	(u16, 'x'),
	(u16, 'y'),
	(u16, 'pressure'),
	(u16, 'altitude'),
	(u16, 'azimuth'),
	(u8[2], ''),
	]

class PacketFrequencyNoise(Struct):
	fields = [
	(u8, ''), # always 8 (number of pairs?)
	(u8, 'start'),
	(u8[2], ''), # always 0
	(u16[16], ''), # 8 pairs of value + sequential index, first index = start*8
	]

class PacketPenGeneral(Struct):
	fields = [
	(u16, 'timestamp'),
	(u8[5], ''), # always 0 on SP7+, not on SLS
	(u8, ''),
	(u32, 'group_counter'), # increases by one for each group of pen packets
	(u8, ''), # always 0
	(u8, ''), # always 0
	(u8, ''), # always 1
	(i8[49], 'padding'), # -1
	]

class PacketPenNoiseMetricsOutput(Struct):
	fields = [
	(i16[32], ''),
	]

class PacketPenDataSelection(Struct):
	fields = [
	(u32[34], ''),
	(i8[4], ''), # something x/y/x/y?
	(i8, 'x0'), (i8, 'y0'), # center col/row of DFT data
	(i8, 'x1'), (i8, 'y1'),
	(u8, ''),
	(u8, 'data_type'),
	(u8, 'seq_num'),
	(i8, 'padding'),
	]

class PacketPenTouchedAntennas(Struct):
	fields = [
	(u8[10], 'x_mask'), # bitmask of antennas touched by fingers in X direction
	(i8, 'x'),
	(i8, 'y'),
	(u16, 'timestamp'),
	(u8[7], 'y_mask'),
	(u8[5], 'x_mask_copy'), # copy of first 5 bytes of x_mask
	(i16, 'padding'), # -1
	]

class PacketPenMetadata(Struct):
	fields = [
	(u32, 'group_counter'), # increases by one for each group of pen packets
	(u8, 'seq_num'), # same as next DFT packet
	(u8, 'data_type'), # same as next DFT packet
	(u8, ''), # alternates 0/1/2/0/1/etc for each group on SP7+, always 6 on SLS
	(i8[9], 'padding'), # -1
	]

class PacketPenDetection(Struct):
	fields = [
	(u32, ''),
	(u32, ''),
	(u8[5], ''),
	(u8, 'seq_num'),
	(u8, 'data_type'),
	(u8, 'flags'),
	]

class PacketPenLift(Struct):
	fields = [
	(i8, ''),
	(i8, ''),
	(i16, 'padding'), # -1
	]

class PacketHeatmapDimensions(Struct):
	fields = [
	(u8, 'height'),
	(u8, 'width'),
	(u8, 'y_min'),
	(u8, 'y_max'),
	(u8, 'x_min'),
	(u8, 'x_max'),
	(u8, 'z_min'),
	(u8, 'z_max'),
	]
		
class HeatmapData(bytes):
	def __repr__(self):
		counts = [0] * 256
		for b in self: counts[b] += 1
		return ' '.join('%i*%02x' % (n,b) for b,n in enumerate(counts) if n)

class Heatmap(Struct):
	fields = [
	(u8, ''),  # always 8
	(u32, ''), # always 0
	(u32, 'size'),
	]

	def read(self, b):
		Struct.read(self, b)
		self.data = HeatmapData(b.read(self.size))

class PacketPenMagnitude(Struct):
	fields = [
	(u8[2], ''),      # always zero
	(u8[2], ''),      # 0 if pen not near screen, 1 or 2 if pen is near screen
	(u8, 'flags'),    # 0, 1 or 8 (bitflags?)
	(i8[3], 'padding'), # -1
	]

	def read(self, b):
		Struct.read(self, b)
		# SP7+: x[64], y[44]
		# SLS:  x[78], y[52]
		self.data = List(u32)
		self.data.read(b)

class PacketPenDftWindow(Struct):
	fields = [
	(u32, 'timestamp'), # counting at approx 8MHz for SP7+, 1MHz for SLS
	(u8, 'num_rows'),
	(u8, 'seq_num'),
	(u8, ''), # usually 1, can be 0 if there are simultaneous touch events
	(u8, ''), # usually 1, can be 0 if there are simultaneous touch events
	(u8, ''), # usually 1, but can be higher (2,3,4) for the first few packets of a pen interaction
	(u8, 'data_type'),
	(i16, 'padding'), # -1
	]

	def read(self, b):
		Struct.read(self, b)
		self.x = List(DftWindowRow, self.num_rows)
		self.x.read(b)
		self.y = List(DftWindowRow, self.num_rows)
		self.y.read(b)

class DftWindowRow(Struct):
	fields = [
	(u32, 'frequency'),
	(u32, 'magnitude'),
	(i16[9], 'real'),
	(i16[9], 'imag'),
	(i8, 'first'),
	(i8, 'last'),
	(i8, 'mid'),
	(i8, ''),
	]

