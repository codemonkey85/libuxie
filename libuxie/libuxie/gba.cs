using System;
using System.Runtime.InteropServices;

namespace LibUxie.GBA {

	public enum Version {
		Unknown, RubySapphire, Emerald, FireRedLeafGreen
	};

	[StructLayout(LayoutKind.Sequential, Pack=1)]
	unsafe struct Footer {
		public ushort sectionId;
		public ushort checksum;
		public uint mark;
		public uint saveIndex;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct Item {
		public ushort index;
		public ushort amount;
	}

	public enum SaveSlot {
		Main,
		Backup
	}

	public class Save {
		private const int BLOCK_COUNT = 14;
		private const int BLOCK_LENGTH = 0x1000;
		private const int UNPACKED_BLOCK_LENGTH = 0xF80;
		private const int FOOTER_LENGTH = 0xC;
		private const uint FOOTER_MARK = 0x08012025;
		private const int UNPACKED_SIZE = 0xD900;
		private const int PACKED_SIZE = 0x20000;
		private const int SAVE_SECTION = 0xE000;

		private const int RSE_SECKEY_OFFSET = 0xAC;
		private const int RSE_SECKEY2_OFFSET = 0x1F4;
		private const int FRLG_SECKEY_OFFSET = 0xAF8;
		private const int FRLG_SECKEY2_OFFSET = 0xF20;

		private const int RSE_STORAGE = UNPACKED_BLOCK_LENGTH + 0x490;
		private const int FRLG_STORAGE = UNPACKED_BLOCK_LENGTH + 0x290;
		private const int RS_FRLG_ITEM_COUNT = 216;
		private const int E_ITEM_COUNT = 236;

		private Version type;
		private byte[] order;
		private byte[] unpacked;
		private int saveIndex;

		/* Unsafe a.k.a. "I got this." */
		private static unsafe Footer *GetFooter(byte[] data, int offset, int block) {
			offset = offset + ((block + 1) * BLOCK_LENGTH - FOOTER_LENGTH);
			fixed(byte* ptr = &data[offset]) {
				return (Footer*)ptr;
			}
		}

		private static int GetStorageOffset(Version type) {
			if(type == Version.RubySapphire || type == Version.Emerald) {
				return RSE_STORAGE;
			}
			if(type == Version.FireRedLeafGreen) {
				return FRLG_STORAGE;
			}
			return 0;
		}

		private static unsafe int GetTypeOffset(byte[] data, SaveSlot slot) {
			Footer *a = GetFooter(data, 0, 0);
			Footer *b = GetFooter(data, SAVE_SECTION, 0);

			if(slot == SaveSlot.Main) {
				if(b->saveIndex > a->saveIndex) {
					return SAVE_SECTION;
				}
				return 0;
			}
			if(a->saveIndex > b->saveIndex) {
				return SAVE_SECTION;
			}
			return 0;
		}

		private unsafe bool IsValid(byte[] data) {
			if(data.Length != PACKED_SIZE) {
				return false;
			}
			Footer *footer = GetFooter(data, 0, 0);
			if(footer->mark != FOOTER_MARK) {
				return false;
			}
			return true;
		}

		private Version DetectVersion() {
			/* Detecting GBA version is a real pain. */
			/* Ruby/Sapphire */
			if(BitConverter.ToInt32(unpacked, RSE_SECKEY_OFFSET) == 0
			&& BitConverter.ToInt32(unpacked, RSE_SECKEY2_OFFSET) == 0) {
				return Version.RubySapphire;
			}

			/* Emerald */
			if(BitConverter.ToInt32(unpacked, RSE_SECKEY_OFFSET)
			== BitConverter.ToInt32(unpacked, RSE_SECKEY2_OFFSET)) {
				return Version.Emerald;
			}

			/* FireRed/LeafGreen */
			if(BitConverter.ToInt32(unpacked, FRLG_SECKEY_OFFSET)
			== BitConverter.ToInt32(unpacked, FRLG_SECKEY2_OFFSET)) {
				return Version.FireRedLeafGreen;
			}

			return Version.Unknown;
		}

		private unsafe Item *GetItem(int index) {
			int offset = GetStorageOffset(type) + index * 4 + 8;
			fixed(byte* ptr = &unpacked[offset]) {
				return (Item*)ptr;
			}
		}

		private unsafe void Crypt() {
			//No (working) encryption in Ruby and Sapphire
			if(type == Version.RubySapphire) {
				return;
			}

			uint key = 0;
			int offset = 0;
			if(type == Version.Emerald) {
				key = BitConverter.ToUInt32(unpacked, RSE_SECKEY_OFFSET);
				offset = GetStorageOffset(type);
				//crypt item data, skip the PC data (not encrypted)
				for(int i = 50; i < E_ITEM_COUNT; ++i) {
					Item* item = GetItem(i);
					item->amount ^= (ushort)key;
				}
			} else if(type == Version.FireRedLeafGreen) {
				key = BitConverter.ToUInt32(unpacked, FRLG_SECKEY_OFFSET);
				offset = GetStorageOffset(type);
				//crypt item data, skip the PC data (not encrypted)
				for(int i = 30; i < RS_FRLG_ITEM_COUNT; ++i) {
					Item* item = GetItem(i);
					item->amount ^= (ushort)key;
				}
			}
			fixed(byte *cash = &unpacked[offset]) {
				uint *icash = (uint *)cash;
				*icash ^= key;
			}
		}

		private unsafe void Unpack(byte[] data, SaveSlot slot) {
			int offset = GetTypeOffset(data, slot);
			order = new byte[BLOCK_COUNT];
			unpacked = new byte[UNPACKED_SIZE];
			/* unpack blocks */
			for(int i = 0; i < BLOCK_COUNT; ++i) {
				//get the block footer
				Footer *footer = GetFooter(data, offset, i);
				order[i] = (byte)footer->sectionId;

				Array.Copy(
					data, offset + i * BLOCK_LENGTH,
					unpacked, footer->sectionId * UNPACKED_BLOCK_LENGTH,
					UNPACKED_BLOCK_LENGTH);
			}
			type = DetectVersion();
			Crypt();
		}

		public bool Load(byte[] data, SaveSlot slot) {
			if(!IsValid(data)) {
				return false;
			}
			Unpack(data, slot);

			return true;
		}

		public Version Version {
			get {
				return type;
			}
		}
	}
}
