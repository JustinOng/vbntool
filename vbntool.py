import sys
import logging
import hashlib
from struct import unpack

logging.basicConfig(level=logging.DEBUG)

if len(sys.argv) != 3:
    sys.exit("Usage: {} <qfile.vbn> <outfile.bin>".format(sys.argv[0]))

with open(sys.argv[1], "rb") as f:
    vbn = f.read()

logging.info("Loaded {} ({} bytes))".format(sys.argv[1], len(vbn)))

if bytes(vbn[0:4]) != b'\x90\x12\x00\x00':
    logging.warning("First 4 bytes should be 0x90120000 but is {}".format(bytes(vbn[0:4])))

qfile_path = vbn[4:4+384].decode("utf-8").strip("\x00")
logging.info("Quarantined File was at: {}".format(qfile_path))

qfm_offset = unpack("<L", vbn[0:4])[0]

# everything from qfm_offset onwards is XORed with 0x5A
# so xor everything with 0x5A

qf = bytearray()
for b in vbn[qfm_offset:]:
    qf.append(b ^ 0x5A)

# https://malwaremaloney.blogspot.com/2018/03/symantec-endpoint-protection-vbn-files.html
# offsets below are calculated relative to qfm_size which is 0x1B27 (6951) in the above article

qfm_size = unpack("<Q", qf[24:32])[0]
logging.debug("Quarantine File Metadata & Header starts at offset {} ({}) stated size {} ({}), actual size {} ({})".format(
        qfm_offset, hex(qfm_offset),
        qfm_size, hex(qfm_size),
        len(qf),
        hex(len(qf))
    ))

qfile_sha1 = bytes(qf[qfm_size + 12:qfm_size + 94]).decode("utf-16")[:-1]
qfile_size = unpack("<Q", qf[qfm_size + 109:qfm_size + 109 + 8 ])[0]

logging.info("Quarantined File has SHA1 hash: {}".format(qfile_sha1))
logging.info("Quarantined File has size: {} bytes".format(qfile_size))

# tracks the start of the current section that we're parsing
section_index = qfm_size + 117

qfile = bytearray()
while section_index < len(qf):
    # first byte denotes type of section
    if qf[section_index] == 0x08:
        logging.debug("Parsing security section")
        security_descriptor_size = unpack("<L", qf[section_index + 1:section_index + 1 + 4])[0]
        security_descriptor = bytes(qf[section_index + 5:section_index + 5 + security_descriptor_size]).decode("utf-16")
        # 1: section index
        # 4: size of security descriptor
        # 5: unknown
        # 1: unknown
        # 8: original quarantined file size
        section_index += 1 + 4 + security_descriptor_size + 5 + 1 + 8
    elif qf[section_index] == 0x09:
        section_size = unpack("<L", qf[section_index + 1:section_index + 1 + 4])[0]
        logging.debug("Parsing data section of size {} from offset {} to {}".format(section_size, qfm_offset + section_index, qfm_offset + section_index + 5 + section_size))

        section_end = section_index + 5 + section_size
        if section_end > len(qf):
            logging.warning("Need to read up to offset {} but data is only {} bytes long".format(section_end, len(qf)))
        
        section_data = qf[section_index + 5 : section_end]

        # section_data is actually XORed with 0xA5
        # since we've already XORed it with 0x5A, undo it
        for b in section_data:
            qfile.append(b ^ 0x5A ^ 0xA5)

        section_index += 1 + 4 + section_size
    else:
        raise Exception("Unknown section header: {}".format(hex(qf[section_index])))

qfile_actual_sha1 = hashlib.sha1(qfile).hexdigest()
if qfile_sha1 != qfile_actual_sha1:
    logging.warning("Actual SHA1({}) of the quarantined file does not match stated SHA1({})!".format(qfile_actual_sha1, qfile_sha1))
