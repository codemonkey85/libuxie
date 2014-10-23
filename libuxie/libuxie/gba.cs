using System;
using System.Runtime.InteropServices;

namespace LibUxie.GBA {
	[StructLayout(LayoutKind.Sequential, Pack=1)]
	struct Footer {
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

	public enum Version {
		Unknown,
		RubySapphire,
		Emerald,
		FireRedLeafGreen
	};

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
		private const int RS_ITEM_COUNT = 216;
		private const int FRLG_ITEM_COUNT = 216;
		private const int E_ITEM_COUNT = 236;

		private const int RSE_PC_ITEM_COUNT = 50;
		private const int FRLG_PC_ITEM_COUNT = 30;

		private Version type;
		private byte[] order;
		private byte[] unpacked;
		private uint saveIndex;

		/* Unsafe a.k.a. "I got this." */
		private static unsafe Footer *GetFooter(byte[] data, int offset, int block) {
			offset = offset + ((block + 1) * BLOCK_LENGTH - FOOTER_LENGTH);
			fixed(byte* ptr = &data[offset]) {
				return (Footer*)ptr;
			}
		}

		private static unsafe int GetTypeOffset(byte[] data, SaveSlot slot) {
			uint a = GetFooter(data, 0, 0)->saveIndex;
			uint b = GetFooter(data, SAVE_SECTION, 0)->saveIndex;
			if(slot == SaveSlot.Main) {
				if(b > a) {
					return SAVE_SECTION;
				}
				return 0;
			}
			if(a > b) {
				return SAVE_SECTION;
			}
			return 0;
		}

		private unsafe bool IsValid(byte[] data) {
			if(data.Length != PACKED_SIZE) {
				return false;
			}
			uint mark = GetFooter(data, 0, 0)->mark;
			if(mark != FOOTER_MARK) {
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

		private unsafe void Crypt() {
			//No (working) encryption in Ruby and Sapphire
			if(type == Version.RubySapphire) {
				return;
			}
			uint key = 0;
			int offset = 0;
			if(type == Version.Emerald) {
				key = BitConverter.ToUInt32(unpacked, RSE_SECKEY_OFFSET);
				offset = RSE_STORAGE;
				//crypt item data, skip the PC data (not encrypted)
				for(int i = RSE_PC_ITEM_COUNT; i < E_ITEM_COUNT; ++i) {
					fixed(byte* ptr = &unpacked[offset + i * 4 + 8]) {
						((Item*)ptr)->amount ^= (ushort)key;
					}
				}
			} else if(type == Version.FireRedLeafGreen) {
				key = BitConverter.ToUInt32(unpacked, FRLG_SECKEY_OFFSET);
				offset = FRLG_STORAGE;
				//crypt item data, skip the PC data (not encrypted)
				for(int i = FRLG_PC_ITEM_COUNT; i < FRLG_ITEM_COUNT; ++i) {
					fixed(byte* ptr = &unpacked[offset + i * 4 + 8]) {
						((Item*)ptr)->amount ^= (ushort)key;
					}
				}
			}
			fixed(byte *cash = &unpacked[offset]) {
				uint *icash = (uint *)cash;
				*icash ^= key;
			}
		}

		public bool Load(byte[] data, SaveSlot slot) {
			if(!IsValid(data)) {
				type = Version.Unknown;
				return false;
			}
			int offset = GetTypeOffset(data, slot);
			order = new byte[BLOCK_COUNT];
			unpacked = new byte[UNPACKED_SIZE];

			unsafe {
				saveIndex = GetFooter(data, offset, 0)->saveIndex;
			}

			/* unpack blocks */
			for(int i = 0; i < BLOCK_COUNT; ++i) {
				//get the block footer
				unsafe {
					order[i] = (byte)GetFooter(data, offset, i)->sectionId;
				}

				Array.Copy(
					data, offset + i * BLOCK_LENGTH,
					unpacked, order[i] * UNPACKED_BLOCK_LENGTH,
					UNPACKED_BLOCK_LENGTH);
			}
			type = DetectVersion();
			Crypt();

			return true;
		}

		public Version Version {
			get {
				return type;
			}
			set {
				type = value;
			}
		}
	}
}
