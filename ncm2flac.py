# 依赖pycrypto库
import binascii
import struct
import base64
import json
import os, sys
from Crypto.Cipher import AES
from joblib import Parallel, delayed
import glob


def dump(file_path, save_path):
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[0 : -(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    f = open(file_path, "rb")
    header = f.read(8)
    assert binascii.b2a_hex(header) == b"4354454e4644414d"
    f.seek(2, 1)
    key_length = f.read(4)
    key_length = struct.unpack("<I", bytes(key_length))[0]
    key_data = f.read(key_length)
    key_data_array = bytearray(key_data)
    for i in range(0, len(key_data_array)):
        key_data_array[i] ^= 0x64
    key_data = bytes(key_data_array)
    cryptor = AES.new(core_key, AES.MODE_ECB)
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    key_length = len(key_data)
    key_data = bytearray(key_data)
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_offset = 0
    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xFF
        key_offset += 1
        if key_offset >= key_length:
            key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c
    meta_length = f.read(4)
    meta_length = struct.unpack("<I", bytes(meta_length))[0]
    meta_data = f.read(meta_length)
    meta_data_array = bytearray(meta_data)
    for i in range(0, len(meta_data_array)):
        meta_data_array[i] ^= 0x63
    meta_data = bytes(meta_data_array)
    meta_data = base64.b64decode(meta_data[22:])
    cryptor = AES.new(meta_key, AES.MODE_ECB)
    decryped = cryptor.decrypt(meta_data)
    meta_data = unpad(decryped).decode("utf-8")[6:]
    meta_data = json.loads(meta_data)

    crc32 = f.read(4)
    crc32 = struct.unpack("<I", bytes(crc32))[0]

    f.seek(5, 1)
    image_size = f.read(4)
    image_size = struct.unpack("<I", bytes(image_size))[0]
    image_data = f.read(image_size)

    file_name = (meta_data["musicName"]).replace("?", "") + "." + meta_data["format"]
    m = open(os.path.join(save_path, file_name), "wb")
    chunk = bytearray()
    ori_total_value = 0
    total_value = 0
    while True:
        chunk = bytearray(f.read(0x8000))
        chunk_length = len(chunk)
        if not chunk:
            break
        for i in range(1, chunk_length + 1):
            ori_total_value += chunk[i - 1]
            j = i & 0xFF
            chunk[i - 1] ^= key_box[
                (key_box[j] + key_box[(key_box[j] + j) & 0xFF]) & 0xFF
            ]
            total_value += chunk[i - 1]
        m.write(chunk)

    m.close()
    f.close()
    print(f"ori_total_value: {ori_total_value}, total_value: {total_value}")


def wrap(file_path, save_path):
    try:
        dump(file_path, save_path)
    except Exception as e:
        print(f"{os.path.basename(file_path)} : {e}")


if __name__ == "__main__":
    sub_path = r"F:\Windows_Data\Desktop\Music"
    save_path = r"F:\Windows_Data\Desktop\ncm_out"
    ncm_list = glob.glob(os.path.join(sub_path, "**", "*.ncm"), recursive=True)
    # for i in ncm_list:
    #     print(os.path.basename(i))
    Parallel(n_jobs=8)(
        delayed(wrap)(path_i, save_path)
        for path_i in ["F:\Windows_Data\Desktop\林俊杰 - 美人鱼.ncm"]
    )
