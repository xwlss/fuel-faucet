## 领水使用教程

1.脚本使用yescaptcha过验证码，需要注册并获取key。没有的可以注册[yescaptcha register](https://yescaptcha.com/i/46I8ZF)。

2.将获取的key在faucet.py文件中替换232行中yes_key='XXX' 的XXX ，修改n为一次想要生成和领水的地址数量。

3.(新增）fuel龙头更新规则，同一ip重复领水将被拒绝，因此需要使用动态ip，已有在使用的动态ip经验的可直接配置242行。没有的可以注册使用[nstproxy register](https://app.nstproxy.com/register?i=EM00Pe).完成后在238行处替换nstproxy_Channel的XXX，239行处替换nstproxy_Password的XXX，删除238，239，240，241行的‘#‘，再删除掉242行即可，或者直接咨询所用代理的客服帮忙配置。

【注意】据反馈这个nstproxy动态代理区域似乎ip blocked的较多，可能是代理设置或者ip池较小原因，建议大家使用更有效的ip代理，如rola-ip，iproyal等。

4.在python3.10版本下运行 python3 faucet.py，如果显示Error：No module named 'XXX' ,请在cmd下运行 pip install XXX，如果是别的报错请自己查询谷歌或者百度，windows下似乎比较麻烦，涉及问题较多，大家自行尝试，mac和linux下运行较为顺畅。

5.运行完成后相关地址、私钥和助记词都会保存在fuel-wallet.txt文件中，请妥善保存。

# fuelwallet-py
python for blockchain fuel official wallet, suport use mnemonic seeds generate fuel address and private key

## pip
```
pip install bip_utils
```

```
# use this project dir`s bech32m.py
from bech32m import encode  # a little different with bitcoin bech32m 
```

## 
```python
from hashlib import sha256
from bip_utils import Bip39SeedGenerator
from bip_utils import Bip32Secp256k1
from bech32m import encode  # a little different with bitcoin bech32m 

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
```

## test
```python
if __name__ == '__main__':
   
    mnemonic = 'seek clean tell token spread parrot pear tray beef desk sponsor plate'
    print(f'mnemonic seeds: {mnemonic}')
    for wallet_index in range(5):
        fl = FuelWallet(mnemonic=mnemonic, wallet_index=wallet_index)

        pk, address = fl.get_address_pk()
        print(f'address index {wallet_index}, address: {address}, pk: 0x{pk}')
```
## result

```
mnemonic seeds: seek clean tell token spread parrot pear tray beef desk sponsor plate
address index 0, address: fuel1gu47yf32mq2khczewvw04el088y34f49fh3vqp4vn8p9yrc28uaqrr3t85, pk: 0x1ef91ec4b2a39d652091f6f217029f5a33eea7e9913da4fa26eb0a79d6663bee
address index 1, address: fuel1pqkzasvy0x2vpvn3humwyq492ccrgqt9t0mvlpdnpkw09tnu9u9sn7hrcq, pk: 0xa9da58f2169d88ea98fff6367c7c6fdcb153c3eef5d8d07881e5f10a8fe55e1a
address index 2, address: fuel142lr9rsntee7lnsxvck7m49fdpfca3vvcmqqvvtfzqwtuuge2qdq5gj259, pk: 0x6af82b17141a6793bc7fb703e98a256e1a446ce0e03c1d8884e3592ad21333a2
address index 3, address: fuel1n0zstx2dntgp64v29wgzsqc4jumcgtse30ws4s3zphpn8rjhzs5s3ttfyf, pk: 0x4423c07fc04d7d73ff34f46bc6b652ed759896bdb689fff1930fc4de98e82d53
address index 4, address: fuel1vqn9mu84v8keec0u8fge8295epr5mn6c74nwekyqn5yspgn8hqdqsg6ryh, pk: 0x0056a68f643de783298adf4ca3269a15110fb02a52937adeef36f53f43ed0b72
```

## import the mnemonic seed to fuel official wallet , get result

<img src="https://github.com/satisfywithmylife/fuel-wallet/assets/30144807/bbbd2a8b-8814-41a5-814c-bc0d4b843ab0" width="30%">

## if you export private key from wallet, you will get same result

## faucet
use yescaptcha to solver captcha

if you dont have YesCaptcha account yet, you can register here：[yescaptcha register](https://yescaptcha.com/i/46I8ZF)。


# last but important!
1. test the result and compare it with main web wallet app(such as: metamask, mathwallet, trustwallet...) before you deposit crypto assets to the address
2. some wallet may get diffrent result, because it may use diffrent derive path to generate wallet
3. learn about hd-wallet principle by your self
