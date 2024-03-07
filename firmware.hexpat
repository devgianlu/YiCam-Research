#include <std/core.pat>
#include <std/mem.pat>
#include <type/leb128.pat>
#include <type/magic.pat>

enum XzCheckType : u8 {
	None   = 0x00,
	CRC32  = 0x01,
	CRC64  = 0x04,
	SHA256 = 0x0a
};

struct XzFlags {
	padding[1];
	XzCheckType check_type;
};

struct XzFilterFlag {
	type::LEB128 filter_id;
	type::LEB128 props_size;
	u8 props[props_size];
};

struct XzBlockHeader {
	u8 size;
	u8 flags;
	if (flags & 0x40 != 0)
		type::LEB128 compressed_size;
	if (flags & 0x80 != 0)
		type::LEB128 uncompressed_size;
	XzFilterFlag filters[(flags & 0x03)+1];
	if ((2 + sizeof(compressed_size) + sizeof(uncompressed_size) + sizeof(filters)) % 4 != 0)
	   padding[4 - ((2 + sizeof(compressed_size) + sizeof(uncompressed_size) + sizeof(filters)) % 4)];
	u32 crc32;
};

struct XzRecord {
	type::LEB128 unpadded_size;
	type::LEB128 uncompressed_size;
};

struct XzIndex {
	padding[1];
	type::LEB128 count;
	XzRecord records[count];
	if ((1 + sizeof(count) + sizeof(records)) % 4 != 0)
	   padding[4 - ((1 + sizeof(count) + sizeof(records)) % 4)];
	u32 crc32;
};

struct XzBlock {
	XzBlockHeader header;
	u8 data[header.compressed_size];
	if (header.compressed_size % 4 != 0)
	   padding[4 - (header.compressed_size % 4)];
	u32 check;
};

struct XzFooter {
	u32 crc32;
	u32 backward_size;
	XzFlags flags;
	type::Magic<"\x59\x5A"> magic;
};

struct XzFile {
	type::Magic<"\xFD\x37\x7A\x58\x5A\x00"> magic;
	XzFlags flags;
	u32 crc32;

	XzBlock block[1];
	XzIndex index;
	XzFooter footer;
};

struct Files {
	XzFile files[while(std::mem::read_string($, 3) == "\xFD\x37\x7A")];
};

// Offsets for "y291ga_9.0.35.00_202111291330.bin" (md5: 02d2885c3255643aef98cad5f8de6fbf)

Files files @ std::mem::find_sequence(0,0xFD,0x37,0x7A,0x58,0x5A,0x00);

XzFile file1 @ $+2;
XzFile file2 @ $+2;
XzFile file3 @ $+124;

XzIndex xzindex_at_0x3C3E4 @ 0x3C3E4;
XzFooter xzfooter_at_0x3C3F0 @ 0x3C3F0;
// XzBlock xzblock_at_0x107 @ 0x107;
