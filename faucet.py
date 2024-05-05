#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
建议运行在py3.10版本上
"""
from collections.abc import ByteString
from enum import Enum
from typing import NamedTuple
from hashlib import sha256
from bip_utils import Bip39SeedGenerator
from bip_utils import Bip32Secp256k1
import requests
import time
from eth_account import Account

class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""

    BECH32 = 1
    BECH32M = 2


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


class DecodeError(ValueError):
    pass


class HrpDoesNotMatch(DecodeError):
    pass


class DecodedAddress(NamedTuple):
    witver: int
    witprog: bytes


def bech32_polymod(values: ByteString) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> bytes:
    """Expand the HRP into values for checksum computation."""
    return bytes([ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp])


def bech32_verify_checksum(hrp: str, data: bytes) -> Encoding:
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    # Invalid checksum
    raise DecodeError()


def bech32_create_checksum(hrp: str, data: bytes, spec: Encoding) -> bytes:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + bytes(6)) ^ const
    return bytes((polymod >> 5 * (5 - i)) & 31 for i in range(6))


def bech32_encode(hrp: str, data: bytes, spec: Encoding) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(bech: str) -> tuple[str, memoryview, Encoding]:
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        # HRP character out of range
        raise DecodeError()
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        # No separator character / Empty HRP / overall max length exceeded
        raise DecodeError()
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        # Invalid data character
        raise DecodeError()
    hrp = bech[:pos]
    data = memoryview(bytes(CHARSET.find(x) for x in bech[pos + 1 :]))
    spec = bech32_verify_checksum(hrp, data)
    return (hrp, data[:-6], spec)


def convertbits(data: ByteString, frombits: int, tobits: int, pad: bool = True) -> bytearray:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = bytearray()
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            # XXX Not covered by tests
            raise DecodeError()
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        # More than 4 padding bits / Non-zero padding in 8-to-5 conversion
        raise DecodeError()
    return ret


def decode(hrp: str, addr: str) -> DecodedAddress:
    """Decode a segwit address."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp:
        raise HrpDoesNotMatch()
    witprog = convertbits(data[1:], 5, 8, False)
    if len(witprog) < 2 or len(witprog) > 40:
        # Invalid program length
        raise DecodeError()
    witver = data[0]
    if witver > 16:
        # Invalid witness version
        raise DecodeError()
    if witver == 0 and len(witprog) != 20 and len(witprog) != 32:
        # Invalid program length for witness version 0 (per BIP141)
        raise DecodeError()
    if witver == 0 and spec != Encoding.BECH32 or witver != 0 and spec != Encoding.BECH32M:
        # Invalid checksum algorithm
        raise DecodeError()
    return DecodedAddress(witver, witprog)


def encode(hrp: str, witprog: ByteString, isbech32m=True) -> str:
    """Encode a segwit address."""
    spec = Encoding.BECH32 if not isbech32m else Encoding.BECH32M
    conve_bytesarray = convertbits(witprog, 8, 5)
    ret = bech32_encode(hrp, conve_bytesarray, spec)
    return ret


    
class FuelWallet():
    
    def __init__(self, mnemonic, password='', wallet_index=0) -> None:
        
        self.mnemonic = mnemonic.strip()
        self.password = password # if have password
        self.derive_default_path = f"m/44'/1179993420'/{wallet_index}'/0/0"
        self.prefix = 'fuel'

    def get_address_pk(self):
        seed_bytes = Bip39SeedGenerator(self.mnemonic).Generate(self.password)
        bip32_mst_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
        bip32_der_ctx = bip32_mst_ctx.DerivePath(self.derive_default_path)
        
        pk: bytes = bip32_der_ctx.PrivateKey().Raw().ToBytes()
        extended_key = Bip32Secp256k1.FromPrivateKey(pk)
        pubkey = extended_key.PublicKey().RawUncompressed().ToBytes().hex()[2:]
        pubkey_bytes = bytes.fromhex(pubkey)
        sha256_bytes = sha256(pubkey_bytes).digest()
        address = encode(self.prefix, sha256_bytes)

        return pk.hex(), address

def get_nocaptcha_google_token(no_captcha_client_key: str):
    headers = {'User-Token': no_captcha_client_key, 'Content-Type': 'application/json', 'Developer-Id': 'CiKFW5'}
    json_data = {
                'referer': 'https://faucet-beta-5.fuel.network/',
                'title':'Fuel Faucet',
                'size':'normal',
                'sitekey':'6Ld3cEwfAAAAAMd4QTs7aO85LyKGdgj0bFsdBfre'
        }



    response = requests.post(url='http://api.nocaptcha.io/api/wanda/recaptcha/universal', headers=headers,
                             json=json_data).json()
    print(response)
    if response.get('status') == 1:
        if response.get('msg') == '验证成功':
            return response['data']['token']
    return False

def get_nocaptcha_cloudflare_cookies(no_captcha_client_key,proxies):
    headers = {'User-Token': no_captcha_client_key, 'Content-Type': 'application/json', 'Developer-Id': 'CiKFW5'}
    json_data = {
    'href': 'https://faucet-beta-5.fuel.network/',
    'proxy':proxies
    }

    response = requests.post(url='http://api.nocaptcha.io/api/wanda/cloudflare/universal', headers=headers,
                             json=json_data).json()
    print(response)
    if response.get('status') == 1:
        if response.get('msg') == '验证成功':
            return response['data']['cookies']
    return False



headers = {
    'accept': 'application/json',
    'accept-language': 'zh-CN,zh;q=0.9',
    'content-type': 'application/json',
    'origin': 'https://faucet-beta-5.fuel.network',
    'priority': 'u=1, i',
    'referer': 'https://faucet-beta-5.fuel.network/',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
}
if __name__ == '__main__':
    Account.enable_unaudited_hdwallet_features()
    #mnemonic = 'awkward smoke lab sauce reward invite job scene amused cement ordinary depend'
    #n为生成和领水地址数量
    n=100
    for i in range(n):
        try:
            account, mnemonic = Account.create_with_mnemonic()
            print(mnemonic)
            fl = FuelWallet(mnemonic=mnemonic, wallet_index=0)
            pk, address = fl.get_address_pk()
            print(f'address: {address}, pk: 0x{pk}')
            
            #更新代理 需要自行购买或者配置 目前市场上很多 大家按自己需要使用
            #以nstproxy示例 
            #在nstproxy网站上注册获取 nstproxy_Channel 和 nstproxy_Password
            #nstproxy_Channel='XXX'
            #nstproxy_Password='XXX'
            #nstproxies = f"{nstproxy_Channel}-residential-country_ANY-r_5m-s_BsqLCLkiVu:{nstproxy_Password}@gw-us.nstproxy.com:24125"
            #proxy = 'all://': nstproxy
            proxy = 'name:pass@127.0.0.1:12345'#以你的代理服务网址或ip和端口替换127.0.0.1:12345
            
            #没有nocaptcha过验证码网站的可以在 https://www.nocaptcha.io/register?c=CiKFW5 上注册获取
            nocap_key='XXX'
            captcha=get_nocaptcha_google_token(nocap_key)
            #print(captcha)
            json_data = {
                    'address': address,
                    'captcha': captcha
                        }
            cookies=get_nocaptcha_cloudflare_cookies(nocap_key,proxy)
            proxies={'all://':f'http://{proxy}'}
            response = requests.post('https://faucet-beta-5.fuel.network/dispense',proxies=proxies, cookies=cookies,verify=False,headers=headers, json=json_data)
            print(response.text)
            
            with open('./fuel-wallet.txt', 'a') as f:
                #将领过水的地址、私钥和助记词保存在fuel-wallet.txt文件中
                f.writelines(address+':'+pk+':'+mnemonic+'\n')
        except Exception as e:
            print(e)
