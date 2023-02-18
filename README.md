Microsoft Surface touch/pen data parser
=======================================

`surface-parser.py` parses MS Surface multitouch/pen data and prints it in a human-readable format.

You must specify one or more data files to parse. Files can be gzipped. It is possible to read from `/dev/hidraw*` directly.

You must specify the input format using one of the following options:
- `--hidraw`: Data read directly from `/dev/hidraw*` device.
- `--ithc`: Data captured from legacy `/dev/ithc` device.
- `--iptstxt`: Data captured using `ipts-dbg/ipts-dump`.
- `--iptsbin`: Data captured using `ipts-dbg/ipts-dump --binary`.

Other options:
- `--dft`:
	Plot pen DFT magnitude data. Uses ANSI escape codes for colors.
	Each line consists of an absolute and a relative timestamp, followed by a group of DFT packets. Each colored column represents the magnitude of a row within a packet.
	The output can be quite wide, you may need to decrease your terminal's font size to fit everything on the screen (or use `less -RS`).


License: Public domain/CC0

