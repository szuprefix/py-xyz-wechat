import base64
import hashlib
import struct
import socket
import time
import random
import string
from Crypto.Cipher import AES


class WXBizMsgCryptError(Exception):
    pass


class PKCS7Encoder:
    block_size = 32

    @classmethod
    def encode(cls, text):
        text_length = len(text)
        amount_to_pad = cls.block_size - (text_length % cls.block_size)
        if amount_to_pad == 0:
            amount_to_pad = cls.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    @classmethod
    def decode(cls, decrypted):
        pad = ord(decrypted[-1])
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]


class WXBizMsgCrypt:
    def __init__(self, token, encoding_aes_key, app_id):
        if len(encoding_aes_key) != 43:
            raise WXBizMsgCryptError("EncodingAESKey 长度必须为 43 位")
        self.token = token
        self.app_id = app_id
        self.aes_key = base64.b64decode(encoding_aes_key + "=")

    def _get_signature(self, timestamp, nonce, encrypt):
        """按字典序排序后做 SHA1"""
        sort_list = sorted([self.token, timestamp, nonce, encrypt])
        sha1 = hashlib.sha1("".join(sort_list).encode("utf-8"))
        return sha1.hexdigest()

    def check_signature(self, msg_signature, timestamp, nonce, encrypt):
        """校验请求是否来自微信"""
        return self._get_signature(timestamp, nonce, encrypt) == msg_signature

    def decrypt(self, encrypt):
        try:
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_key[:16])
            decrypted = cipher.decrypt(base64.b64decode(encrypt))

            # 先按 PKCS7 去填充（在 bytes 上做）
            pad = decrypted[-1]
            if pad < 1 or pad > 32:
                raise ValueError("非法填充")
            decrypted = decrypted[:-pad] if pad else decrypted

            # 前 16 字节随机数
            content = decrypted[16:]
            if len(content) < 4:
                raise WXBizMsgCryptError("解密内容长度不足")

            # 4 字节消息长度（网络字节序）
            xml_len = socket.ntohl(struct.unpack("I", content[:4])[0])
            xml_content = content[4: 4 + xml_len]
            from_appid = content[4 + xml_len:]

            if from_appid.decode("utf-8") != self.app_id:
                raise WXBizMsgCryptError("AppID 校验失败")

            return xml_content.decode("utf-8")
        except WXBizMsgCryptError:
            raise
        except Exception as e:
            raise WXBizMsgCryptError(f"解密失败: {e}")

    def decrypt_msg(self, msg_signature, timestamp, nonce, encrypt):
        """
        完整的验签 + 解密入口
        """
        if not self.check_signature(msg_signature, timestamp, nonce, encrypt):
            raise WXBizMsgCryptError("签名校验失败")
        return self.decrypt(encrypt)