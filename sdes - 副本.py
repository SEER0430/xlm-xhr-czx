import tkinter as tk
from tkinter import messagebox
import time
import secrets
import base64
# S-DES算法部分
# S-DES算法部分
def permute(bits, perm):
    return [bits[i - 1] for i in perm]

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]


def generate_keys(key):
    # 初始P10置换
    key = permute(key, [3, 5, 2, 7, 4, 10, 1, 9, 6, 8])

    # 分组并左移1位
    left_half = left_shift(key[:5], 1)
    right_half = left_shift(key[5:], 1)

    # K1通过P8置换生成
    K1 = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])

    # 左移2位生成K2
    left_half = left_shift(left_half, 2)
    right_half = left_shift(right_half, 2)
    K2 = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])

    return K1, K2

def sbox(input_bits, sbox_table):
    row = (input_bits[0] << 1) + input_bits[3]
    col = (input_bits[1] << 1) + input_bits[2]
    output = sbox_table[row][col]
    return [(output >> 1) & 1, output & 1]

def f(right, subkey):
    # 扩展置换表 EP
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]

    # S盒S0和S1
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    S1 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

    # 右边的R通过扩展置换EP后，与子密钥进行异或
    expanded_right = permute(right, EP)
    xor_result = [expanded_right[i] ^ subkey[i] for i in range(8)]

    # 将异或结果分为左右部分，进入S盒
    left_sbox = sbox(xor_result[:4], S0)
    right_sbox = sbox(xor_result[4:], S1)

    # S盒结果通过P4置换
    return permute(left_sbox + right_sbox, P4)

def fk(bits, subkey):
    # 将bits分为左右两部分
    left, right = bits[:4], bits[4:]
    # 右边部分通过f函数处理，并与左边部分进行异或
    result = [left[i] ^ f(right, subkey)[i] for i in range(4)]
    return result + right

# 加密过程
def encrypt(plaintext, key):
    # 初始置换IP表
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

    # 生成K1和K2
    K1, K2 = generate_keys(key)

    # 初始置换
    bits = permute(plaintext, IP)

    # 第一轮加密
    bits = fk(bits, K1)
    # 左右交换
    bits = bits[4:] + bits[:4]

    # 第二轮加密
    bits = fk(bits, K2)

    # 逆置换
    ciphertext = permute(bits, IP_inv)
    return ciphertext

# 解密过程
def decrypt(ciphertext, key):
    # 初始置换IP表
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

    # 生成K1和K2
    K1, K2 = generate_keys(key)

    # 初始置换
    bits = permute(ciphertext, IP)

    # 第一轮解密使用K2
    bits = fk(bits, K2)
    # 左右交换
    bits = bits[4:] + bits[:4]

    # 第二轮解密使用K1
    bits = fk(bits, K1)

    # 逆置换
    plaintext = permute(bits, IP_inv)
    return plaintext

def str_to_bin_list(text, length):
    return [int(bit) for bit in text.zfill(length)]

def bin_list_to_str(bin_list):
    return ''.join(str(bit) for bit in bin_list)


# 新增ASCII字符串与二进制的相互转换函数
def ascii_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)


def bin_to_ascii(bin_str):
    chars = [chr(int(bin_str[i:i + 8], 2)) for i in range(0, len(bin_str), 8)]
    return ''.join(chars)


# ASCII加密
def encrypt_ascii(plaintext, key):
    binary_plaintext = ascii_to_bin(plaintext)

    if len(binary_plaintext) % 8 != 0:
        binary_plaintext = binary_plaintext.zfill((len(binary_plaintext) // 8 + 1) * 8)

    result = []
    for i in range(0, len(binary_plaintext), 8):
        plaintext_bits = str_to_bin_list(binary_plaintext[i:i + 8], 8)
        result.extend(encrypt(plaintext_bits, key))

    # 将结果的二进制列表转换为ASCII字符串
    binary_result = bin_list_to_str(result)
    return bin_to_ascii(binary_result)


# ASCII解密
def decrypt_ascii(ciphertext, key):
    binary_ciphertext = ascii_to_bin(ciphertext)

    result = []
    for i in range(0, len(binary_ciphertext), 8):
        ciphertext_bits = str_to_bin_list(binary_ciphertext[i:i + 8], 8)
        result.extend(decrypt(ciphertext_bits, key))

    # 将结果的二进制列表转换为ASCII字符串
    binary_result = bin_list_to_str(result)
    return bin_to_ascii(binary_result)


# GUI部分
root = tk.Tk()
root.title("欢迎使用S-DES加解密系统！")
root.configure(bg='lightblue')
root.geometry("600x400")

title_font = ("Times", 16, "bold")
label_font = ("Times", 12)
button_font = ("Times", 12, "bold")
result_font = ("Times", 12, "italic")

main_frame = tk.Frame(root, bg='lightblue')
main_frame.pack(expand=True)


def show_home():
    for widget in main_frame.winfo_children():
        widget.destroy()

    tk.Label(main_frame, text="选择操作：", font=title_font, bg='lightblue').grid(row=0, column=0, columnspan=4, pady=20)

    ascii_button = tk.Button(main_frame, text="ASCII", width=20, font=button_font, command=show_ascii_mode)
    ascii_button.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

    binary_button = tk.Button(main_frame, text="二进制", width=20, font=button_font, command=show_binary_mode)
    binary_button.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

    ascii_button = tk.Button(main_frame, text="暴力破解", width=20, font=button_font, command=brute_force_sdes)
    ascii_button.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

    binary_button = tk.Button(main_frame, text="封闭测试", width=20, font=button_font, command=find_all_keys_sdes)
    binary_button.grid(row=4, column=0, padx=20, pady=10, sticky="ew")



def show_ascii_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()

    tk.Label(main_frame, text="ASCII明文/密文：", font=label_font, bg='lightblue').grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="10-bit密钥：", font=label_font, bg='lightblue').grid(row=1, column=0, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font)
    key_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果", font=result_font, bg='lightblue')
    result_label.grid(row=3, columnspan=2, pady=10)

    result_text = tk.Text(main_frame, height=4, width=50, font=label_font, wrap='word')  # 可选中的Text控件
    result_text.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    button_frame = tk.Frame(main_frame, bg='lightblue')
    button_frame.grid(row=2, columnspan=2, pady=10)

    def encrypt_ascii_action():
        plaintext = text_entry.get()
        key = key_entry.get()

        if len(key) != 10 or not all(bit in '01' for bit in key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        key_bits = str_to_bin_list(key, 10)
        result = encrypt_ascii(plaintext, key_bits)

        result_text.delete(1.0, tk.END)  # 清除之前的内容
        result_text.insert(tk.END, result)  # 显示加密后的结果

    def decrypt_ascii_action():
        ciphertext = text_entry.get()
        key = key_entry.get()

        if len(key) != 10 or not all(bit in '01' for bit in key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        key_bits = str_to_bin_list(key, 10)
        result = decrypt_ascii(ciphertext, key_bits)

        result_text.delete(1.0, tk.END)  # 清除之前的内容
        result_text.insert(tk.END, result)  # 显示解密后的结果

    tk.Button(button_frame, text="加密", font=button_font, command=encrypt_ascii_action, width=20).pack(pady=5)
    tk.Button(button_frame, text="解密", font=button_font, command=decrypt_ascii_action, width=20).pack(pady=5)
    tk.Button(button_frame, text="返回", font=button_font, command=show_home, width=20).pack(pady=5)


def show_binary_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()

    tk.Label(main_frame, text="8-bit二进制明文/密文：", font=label_font, bg='lightblue').grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="10-bit密钥：", font=label_font, bg='lightblue').grid(row=1, column=0, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font)
    key_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果", font=result_font, bg='lightblue')
    result_label.grid(row=3, columnspan=2, pady=10)

    button_frame = tk.Frame(main_frame, bg='lightblue')
    button_frame.grid(row=2, columnspan=2, pady=10)

    def encrypt_binary_action():
        plaintext = text_entry.get()
        key = key_entry.get()

        if len(plaintext) != 8 or not all(bit in '01' for bit in plaintext):
            messagebox.showerror("错误", "请输入8位二进制明文！")
            return
        if len(key) != 10 or not all(bit in '01' for bit in key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        plaintext_bits = str_to_bin_list(plaintext, 8)
        key_bits = str_to_bin_list(key, 10)

        result = encrypt(plaintext_bits, key_bits)
        result_label.config(text="加密后密文: " + bin_list_to_str(result))

    def decrypt_binary_action():
        ciphertext = text_entry.get()
        key = key_entry.get()

        if len(ciphertext) != 8 or not all(bit in '01' for bit in ciphertext):
            messagebox.showerror("错误", "请输入8位二进制密文！")
            return
        if len(key) != 10 or not all(bit in '01' for bit in key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        ciphertext_bits = str_to_bin_list(ciphertext, 8)
        key_bits = str_to_bin_list(key, 10)

        result = decrypt(ciphertext_bits, key_bits)
        result_label.config(text="解密后明文: " + bin_list_to_str(result))

    tk.Button(button_frame, text="加密", font=button_font, command=encrypt_binary_action, width=20).pack(pady=5)
    tk.Button(button_frame, text="解密", font=button_font, command=decrypt_binary_action, width=20).pack(pady=5)
    tk.Button(button_frame, text="返回", font=button_font, command=show_home, width=20).pack(pady=5)



# 暴力破解函数
def brute_force_sdes():
    # 清空主框架中的所有小部件
    ## 工具函数：将字符串转换为二进制列表
    def str_to_bin_list(data, bit_length=8):
        bin_data = []
        for char in data:
            bin_values = bin(ord(char))[2:].zfill(bit_length)
            bin_data.extend([int(bit) for bit in bin_values])
        return bin_data

    # 工具函数：将Base64字符串转换为二进制数据
    def base64_to_bin(base64_data):
        byte_array = base64.b64decode(base64_data.encode('utf-8'))
        bin_data = ''.join([bin(byte)[2:].zfill(8) for byte in byte_array])
        return [int(bit) for bit in bin_data]
    for widget in main_frame.winfo_children():
        widget.destroy()

    # 创建输入框和标签
    tk.Label(main_frame, text="明文：", font=label_font, bg='lightblue').grid(row=0, column=0, pady=10)
    plaintext_entry = tk.Entry(main_frame, font=label_font)
    plaintext_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="密文（Base64）：", font=label_font, bg='lightblue').grid(row=1, column=0, pady=10)
    ciphertext_entry = tk.Entry(main_frame, font=label_font)
    ciphertext_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果", font=result_font, bg='lightblue')
    result_label.grid(row=3, columnspan=2, pady=10)

    button_frame = tk.Frame(main_frame, bg='lightblue')
    button_frame.grid(row=2, columnspan=2, pady=10)

    def find_key():
        plaintext = plaintext_entry.get()
        ciphertext = ciphertext_entry.get()

        # 转换明文和密文
        plaintext_bits = str_to_bin_list(plaintext)
        cipher_bits = base64_to_bin(ciphertext)

        # 确保明文和密文的块数一致
        if len(plaintext_bits) // 8 != len(cipher_bits) // 8:
            messagebox.showerror("错误", "明文和密文的块数不一致。")
            return
        # 记录开始时间
        start_time = time.time()

        # 遍历所有可能的10位密钥
        for key_int in range(0, 1024):
            # 将整数转换为10位二进制列表
            key_str = bin(key_int)[2:].zfill(10)
            key = [int(bit) for bit in key_str]

            # 加密明文
            encrypted_bits = []
            for i in range(0, len(plaintext_bits), 8):
                block = plaintext_bits[i:i + 8]
                if len(block) < 8:
                    block += [0] * (8 - len(block))
                cipher_block = encrypt(block, key)  # 假设 encrypt 函数已定义
                encrypted_bits.extend(cipher_block)

            # 比较加密结果与给定密文
            if encrypted_bits == cipher_bits[:len(encrypted_bits)]:
                messagebox.showinfo("找到匹配密钥", f"找到的密钥: {key_str}")  # 弹出匹配密钥
                return  # 找到密钥后退出函数

        # 如果没有找到匹配密钥
        messagebox.showinfo("未找到密钥", "未能找到匹配的密钥。")
        # 记录结束时间
        end_time = time.time()
        print(end_time-start_time)

    # 添加按钮以触发暴力破解
    tk.Button(button_frame, text="暴力破解密钥", font=button_font, command=find_key, width=20).pack(pady=5)
    tk.Button(button_frame, text="返回", font=button_font, command=show_home, width=20).pack(pady=5)

# 新增函数：查找所有可能的密钥
def find_all_keys_sdes():
    # 清空主框架中的所有小部件
    ## 工具函数：将字符串转换为二进制列表
    def str_to_bin_list(data, bit_length=8):
        bin_data = []
        for char in data:
            bin_values = bin(ord(char))[2:].zfill(bit_length)
            bin_data.extend([int(bit) for bit in bin_values])
        return bin_data

    # 工具函数：将Base64字符串转换为二进制数据
    def base64_to_bin(base64_data):
        byte_array = base64.b64decode(base64_data.encode('utf-8'))
        bin_data = ''.join([bin(byte)[2:].zfill(8) for byte in byte_array])
        return [int(bit) for bit in bin_data]

    for widget in main_frame.winfo_children():
        widget.destroy()

    # 创建输入框和标签
    tk.Label(main_frame, text="明文：", font=label_font, bg='lightblue').grid(row=0, column=0, pady=10)
    plaintext_entry = tk.Entry(main_frame, font=label_font)
    plaintext_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="密文（Base64）：", font=label_font, bg='lightblue').grid(row=1, column=0, pady=10)
    ciphertext_entry = tk.Entry(main_frame, font=label_font)
    ciphertext_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果", font=result_font, bg='lightblue')
    result_label.grid(row=3, columnspan=2, pady=10)

    button_frame = tk.Frame(main_frame, bg='lightblue')
    button_frame.grid(row=2, columnspan=2, pady=10)

    def find_key():
        plaintext = plaintext_entry.get()
        ciphertext = ciphertext_entry.get()

        # 转换明文和密文
        plaintext_bits = str_to_bin_list(plaintext)
        cipher_bits = base64_to_bin(ciphertext)

        # 确保明文和密文的块数一致
        if len(plaintext_bits) // 8 != len(cipher_bits) // 8:
            messagebox.showerror("错误", "明文和密文的块数不一致。")
            return
        # 加密明文
        # 存储所有找到的匹配密钥
        found_keys = []

        # 遍历所有可能的10位密钥
        for key_int in range(0, 1024):
            # 将整数转换为10位二进制列表
            key_str = bin(key_int)[2:].zfill(10)
            key = [int(bit) for bit in key_str]



            encrypted_bits = []
            for i in range(0, len(plaintext_bits), 8):
                block = plaintext_bits[i:i + 8]
                if len(block) < 8:
                    block += [0] * (8 - len(block))
                cipher_block = encrypt(block, key)  # 假设 encrypt 函数已定义
                encrypted_bits.extend(cipher_block)

            # 比较加密结果与给定密文
            if encrypted_bits == cipher_bits[:len(encrypted_bits)]:
                    found_keys.append(key_str)  # 存储找到的密钥

            # 显示所有找到的密钥
        if found_keys:
                messagebox.showinfo("找到匹配密钥", f"找到的密钥: {', '.join(found_keys)}")  # 弹出所有匹配密钥
        else:
                messagebox.showinfo("未找到密钥", "未能找到匹配的密钥。")

    # 添加按钮以寻找秘钥
    tk.Button(button_frame, text="所有可能的秘钥：", font=button_font, command=find_key, width=20).pack(pady=5)
    tk.Button(button_frame, text="返回", font=button_font, command=show_home, width=20).pack(pady=5)

show_home()
root.mainloop()
show_home()
root.mainloop()

