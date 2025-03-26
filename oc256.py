import struct
import tkinter as tk
from tkinter import messagebox

# OC-256 常量（扩展版）
oc_k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0x1f6e4c8b, 0x2a7d9e5c, 0x3b8f1a6d, 0x4c9e2b7e, 0x5d0f3c8f, 0x6e1f4d9f, 0x7f2f5eaf, 0x8f3f6fbf,
    0x9f4f7fcf, 0xaf5f8fdf, 0xbf6f9fef, 0xcf7faffe, 0xdf8fbfff, 0xef9fcfff, 0xffafdfef, 0x0fbfefff,
    0x1fcffeff, 0x2fdfffff, 0x3fefffff, 0x4ffffff0, 0x5ffffff1, 0x6ffffff2, 0x7ffffff3, 0x8ffffff4,
    0x9ffffff5, 0xaffffff6, 0xbffffff7, 0xcffffff8, 0xdffffff9, 0xeffffffa, 0xfffffffb, 0x0fffffff,
    0x1ffffffe, 0x2ffffffd, 0x3ffffffc, 0x4ffffffb, 0x5ffffffa, 0x6ffffff9, 0x7ffffff8, 0x8ffffff7
]

# OC-256 初始哈希值
oc_h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, 0x12345678, 0x9abcdef0
]

# 右旋转函数
def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# 消息调度函数
def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

# OC-256 主循环
def oc256_transform(chunk, hash_values):
    w = [0] * 128
    for i in range(16):
        w[i] = struct.unpack(">I", chunk[i * 4:(i + 1) * 4])[0]
    for i in range(16, 128):
        w[i] = (sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h, i, j = hash_values

    for k in range(128):
        temp1 = (h + Sigma1(e) + ((e & f) ^ (~e & g)) + oc_k[k % len(oc_k)] + w[k]) & 0xFFFFFFFF
        temp2 = (Sigma0(a) + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

    hash_values[0] = (hash_values[0] + a) & 0xFFFFFFFF
    hash_values[1] = (hash_values[1] + b) & 0xFFFFFFFF
    hash_values[2] = (hash_values[2] + c) & 0xFFFFFFFF
    hash_values[3] = (hash_values[3] + d) & 0xFFFFFFFF
    hash_values[4] = (hash_values[4] + e) & 0xFFFFFFFF
    hash_values[5] = (hash_values[5] + f) & 0xFFFFFFFF
    hash_values[6] = (hash_values[6] + g) & 0xFFFFFFFF
    hash_values[7] = (hash_values[7] + h) & 0xFFFFFFFF
    hash_values[8] = (hash_values[8] + i) & 0xFFFFFFFF
    hash_values[9] = (hash_values[9] + j) & 0xFFFFFFFF

# OC-256 主函数（支持密码）
def oc256(input_data, password=""):
    bit_length = len(input_data) * 8
    padded = bytearray(password + input_data, "utf-8")  # 将密码与输入数据结合
    padded.append(0x80)

    while (len(padded) * 8) % 512 != 448:
        padded.append(0x00)

    padded += struct.pack(">Q", bit_length)

    hash_values = oc_h[:]

    for i in range(0, len(padded), 64):
        oc256_transform(padded[i:i + 64], hash_values)

    result = ""
    for value in hash_values[:10]:
        result += f"{value % 100000:05x}"
    return result[:50]

# 加密函数
def encrypt(input_data, password):
    encrypted = bytearray()
    for i, char in enumerate(input_data.encode("utf-8")):
        encrypted.append(char ^ ord(password[i % len(password)]))  # 按位异或加密
    return encrypted.hex()

# 解密函数
def decrypt(encrypted_data, password):
    encrypted_bytes = bytearray.fromhex(encrypted_data)
    decrypted = bytearray()
    for i, char in enumerate(encrypted_bytes):
        decrypted.append(char ^ ord(password[i % len(password)]))  # 按位异或解密
    try:
        return decrypted.decode("utf-8")  # 尝试解码为 UTF-8
    except UnicodeDecodeError:
        return decrypted.decode("latin1")  # 如果 UTF-8 解码失败，尝试使用 Latin-1 解码

def run_oc256():
    input_data = input_text.get("1.0", tk.END).strip()
    password = password_entry.get()
    if not input_data or not password:
        messagebox.showerror("错误", "请输入内容和密码！")
        return
    hash_value = oc256(input_data, password)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"OC-256 哈希值: {hash_value}")

def run_encrypt():
    input_data = input_text.get("1.0", tk.END).strip()
    password = password_entry.get()
    if not input_data or not password:
        messagebox.showerror("错误", "请输入内容和密码！")
        return
    encrypted_data = encrypt(input_data, password)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"加密结果: {encrypted_data}")

def run_decrypt():
    encrypted_data = input_text.get("1.0", tk.END).strip()
    password = password_entry.get()
    if not encrypted_data or not password:
        messagebox.showerror("错误", "请输入内容和密码！")
        return
    try:
        decrypted_data = decrypt(encrypted_data, password)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"解密结果: {decrypted_data}")
    except Exception as e:
        messagebox.showerror("解密失败", f"解密失败: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("OC-256 工具")

    # 输入框
    tk.Label(root, text="输入内容:").grid(row=0, column=0, sticky="w")
    input_text = tk.Text(root, height=5, width=50)
    input_text.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

    # 密码框
    tk.Label(root, text="密码:").grid(row=2, column=0, sticky="w")
    password_entry = tk.Entry(root, show="*", width=30)
    password_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=5)

    # 按钮
    tk.Button(root, text="计算哈希", command=run_oc256).grid(row=3, column=0, padx=10, pady=5)
    tk.Button(root, text="加密", command=run_encrypt).grid(row=3, column=1, padx=10, pady=5)
    tk.Button(root, text="解密", command=run_decrypt).grid(row=3, column=2, padx=10, pady=5)

    # 输出框
    tk.Label(root, text="结果:").grid(row=4, column=0, sticky="w")
    result_text = tk.Text(root, height=5, width=50, state="normal")
    result_text.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

    root.mainloop()
