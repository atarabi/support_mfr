import sys
import platform
import pathlib
import struct

KEY_TABLE = {
    "kind": "Kind",
    "vers": "Version",
    "prty": "Priority",
    "host": "RequiredHost",
    "name": "Name",
    "catg": "Category",
    "m68k": "Code68k",
    "68fp": "Code68kFPU",
    "pwpc": "CodePowerPC",
    "ppcb": "CodeCarbonPowerPC",
    "mach": "CodeMachOPowerPC",
    "mi32": "CodeMacIntel32",
    "mi64": "CodeMacIntel64",
    "ma64": "CodeMacARM64",
    "wx86": "CodeWin32X86",
    "8664": "CodeWin64X86",
    "mode": "SupportedModes",
    "fici": "FilterCaseInfo",
    "expf": "ExportFlags",
    "fxio": "SupportsPOSIXIO",
    "fmTC": "FmtFileType",
    "RdTy": "ReadTypes",
    "WrTy": "WriteTypes",
    "fftT": "FilteredTypes",
    "RdEx": "ReadExtensions",
    "WrEx": "WriteExtensions",
    "fftE": "FilteredExtensions",
    "fmtf": "FormatFlags",
    "fmip": "FormatICCFlags",
    "mxsz": "FormatMaxSize",
    "mxch": "FormatMaxChannels",
    "ePVR": "AE_PiPL_Version",
    "eSVR": "AE_Effect_Spec_Version",
    "eVER": "AE_Effect_Version",
    "eINF": "AE_Effect_Info_Flags",
    "eGLO": "AE_Effect_Global_OutFlags",
    "eGL2": "AE_Effect_Global_OutFlags_2",
    "eMNA": "AE_Effect_Match_Name",
    "FXMF": "AE_ImageFormat_Extension_Info",
    "aeRD": "AE_Reserved",
    "aeFL": "AE_Reserved_Info",
}


def decode_key(bytes: bytearray):
    key = "".join(reversed(bytes.decode()))
    if key in KEY_TABLE:
        return KEY_TABLE[key]
    return key


KIND_TABLE = {
    b"TKFe": "AEEffect",
    b"FIXF": "AEImageFormat",
    b"TSFe": "AEAccelerator",
    b"pgEA": "AEGeneral",
    b"xgEA": "AEGP",
    b"FPFe": "AEForeignProjectFormat",
}


def decode_kind(kind: bytearray):
    kind = bytes(kind)
    if kind in KIND_TABLE:
        return KIND_TABLE[kind]
    return "Unknown"


def decode_str(bytes: bytearray):
    return struct.unpack(f"{len(bytes)}s", bytes)[0].decode("ascii").strip()


PIPL_OVERRIDE_FLAG = 1 << 23
MFR_FLAG = 1 << 27


def execute(path: pathlib.Path):
    bytes = bytearray(path.read_bytes())
    try:
        pos = bytes.index(b'P\x00I\x00P\x00L\x00')
    except ValueError:
        print("PiPL cannot be found")
        return

    done = False

    do_edit_spec_version = False
    spec_version_pos = None
    out_flags = None
    out_flags_pos = None
    do_edit_out_flags2 = False
    out_flags2 = None
    out_flags2_pos = None

    try:
        while True:
            pos = bytes.index(b"MIB8", pos + 1)
            pos += 4
            key = decode_key(bytes[pos:pos + 4])
            pos += 4
            count = struct.unpack("<ll", bytes[pos:pos + 8])[1]
            count += (4 - count % 4) % 4
            pos += 8

            print(f"---{key}---")
            if key == "Kind":
                print(f"{decode_kind(bytes[pos:pos+4])}")
            elif key in ("Name", "Category", "Code68k", "Code68kFPU",
                        "CodePowerPC", "CodeCarbonPowerPC", "CodeMachOPowerPC",
                        "CodeMacIntel32", "CodeMacIntel64", "CodeMacARM64",
                        "CodeWin32X86", "CodeWin64X86", "AE_Effect_Match_Name"):
                print(f"{decode_str(bytes[pos:pos+count])}")
            elif key in ("AE_PiPL_Version", "AE_Effect_Version",
                        "AE_Effect_Info_Flags"):
                print(f"{struct.unpack('<l', bytes[pos:pos+4])[0]}")
            elif key == "AE_Effect_Spec_Version":
                spec_version = struct.unpack("<HH", bytes[pos:pos + 4])
                spec_version_pos = pos
                print(f"{spec_version[0]}, {spec_version[1]}")
                if spec_version[0] < 13 or (spec_version[0] == 13
                                            and spec_version[1] < 25):
                    do_edit_spec_version = True
            elif key == "AE_Effect_Global_OutFlags":
                out_flags = struct.unpack("<l", bytes[pos:pos + 4])[0]
                out_flags_pos = pos
                print(f"{out_flags}")
            elif key == "AE_Effect_Global_OutFlags_2":
                out_flags2 = struct.unpack("<l", bytes[pos:pos + 4])[0]
                out_flags2_pos = pos
                if not out_flags2 & MFR_FLAG:
                    do_edit_out_flags2 = True
                print(f"{out_flags2}")
            elif key == "AE_Reserved_Info":
                print(f"{struct.unpack('<l', bytes[pos:pos+4])[0]}")
                if do_edit_spec_version:
                    bytes[spec_version_pos:spec_version_pos + 4] = struct.pack(
                        "<HH", 13, 25)
                    done = True
                if do_edit_out_flags2:
                    bytes[out_flags_pos:out_flags_pos + 4] = struct.pack(
                        "<l", out_flags | PIPL_OVERRIDE_FLAG)
                    bytes[out_flags2_pos:out_flags2_pos + 4] = struct.pack(
                        "<l", out_flags2 | MFR_FLAG)
                    done = True
                do_edit_spec_version = False
                do_edit_out_flags2 = False
    except ValueError:
        pass

    if done:
        new_path = pathlib.Path(f'{path.parent}/{path.stem}_mfr.aex')
        new_path.write_bytes(bytes)


def main():
    if platform.system() != "Windows":
        print("This script is available only on Windows.")
        return

    argv = sys.argv
    if len(argv) < 2:
        print("Usage: python support_mfr.py [target.aex]")
        return

    aex_path = argv[1]
    aex = pathlib.Path(aex_path)
    if not aex.exists():
        print(f"{aex} doesn't exist")
        return
    elif aex.suffix != '.aex':
        print("Only aex is supported")
        return

    execute(aex)


if __name__ == "__main__":
    main()
