from hashlib import sha256

input = "root-me.org"
content_m_key = []
for i in range(len(input)):
    content_m_key += chr(ord(input[i]) - i + 0x14)

# print(content_m_key)
# => ['\x86', '\x82', '\x81', '\x85', '=', '|', 's', ';', '{', '}', 'q']

serial = ""
for val in content_m_key:
    serial += hex(ord(val)).lstrip('0x')

print("Login:", input)
print("Serial:", serial)    