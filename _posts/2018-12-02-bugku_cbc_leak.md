---
layout: post
title: 'bugku login4'
subtitle: 'CBC字节翻转攻击'
tags: 安全 cryptography ctf web
---

# 0x00

[BugkuCTF login4](https://ctf.bugku.com/challenges#login4)

先来看一下CBC的加密方式：![](/assets/img/md/Sat-Nov-17-23:26:35-2018_611064.jpg)

可以看到在加密前明文会与初始化向量IV（或是前一个密文分组）进行异或运算，这样在解密时就可以通过修改初始化向量（或是前一个密文分组）来影响到原有的明文信息，这就是CBC字节翻转攻击 

本题从截取的请求中可以看到，可以控制初始化向量IV和密文信息，通过控制返回的密文信息而控制自己的身份，当身份为admin时，可以获取到flag。这里就可以用CBC字节翻转攻击来修改自己身份为admin，获取flag。

![](/assets/img/md/2018-12-01-132334333344.png)

# 0x01 

以`admIn`登录，这样让前一个分组的密文（或是初始化向量IV）中`I`对应的那一位与`32`进行异或运算，在经过服务端解密后就可以得到`admin`了

目前还不知道是哪一位会对应到字母`I`，而且如果是密文分组中的某一位对应的话，直接修改密文分组会导致该分组在服务端解密后的数据混乱，不过我们目前可以控制*初始化向量IV*，所以可以先遍历修改一下这个初始化向量IV（在base64解码后可以看到是16位），让每一位与32进行异或，如果刚好修改到`I`对应的那一位就直接获取到了flag

```python
session = requests.session()

url = "http://123.206.31.85:49168/index.php"
proxies = {
    'http': '127.0.0.1:8080'
}
param = {
    'username': 'admIn',
    'password': '',
    'submit': 'Login'
}


def replace_cookie(_key, _cookie, _i=0, _v=None):
    """
    设置cookie中的 iv 或 cipher
    :param _key: 键
    :param _cookie: cookie
    :param _i: 设置第几个（设置了 _v 后则忽略这个参数）
    :param _v: 直接设置值（为None时忽略）
    :return:
    """
    if _v:
        _cookie.set(_key, _v, path="/", domain="123.206.31.85")
        return

    _value = parse.unquote(_cookie[_key])
    _value = base64.b64decode(_value)
    _arr = bytearray(_value)
    _arr[_i] = _arr[_i] ^ 32        # 大小写转换

    _cookie.set(_key, parse.quote(base64.b64encode(bytes(_arr))), path="/", domain="123.206.31.85")


def deal_send(_key, _i):
    """
    让 iv 或是 cipher 的第 _i 个字节进行变换后发送请求
    :param _key: iv / cipher
    :param _i: 调整第 _i 个字节
    :return: 服务器返回的数据
    """
    session.cookies.clear()
    session.post(url, param, proxies=proxies) 	# 由于同一个cookie用几次就失效了，所以每次循环都重新登录一下
    replace_cookie(_key, session.cookies, _i)
    _rest = session.get(url, proxies=proxies, headers={'flag': "{}->{}".format(_key, _i)})  # 这个headers头用来标识一下，方便burp中查看
    if 'flag' in _rest.text and 'Only admin can see flag' not in _rest.text:                # flag
        print(_i)
        print(session.cookies)
        print(_rest.text)
        print()
    return _rest.text


def step1():
    for i in range(16):
        deal_send('iv', i)

if __name__ == '__main__':
    step1()
```

在运行完之后可以看到并没有任何输出，说明只修改初始化向量是没用的，不过从返回信息中可以看到一点有价值的信息：

![value](/assets/img/md/2018-12-09-3223637348.jpg)

可以看到一些返回中提示序列化失败，并返回了base64编码后的数据

在对这些数据解码后可以看到我们的密文实际对应的明文信息应该是：

```json
a:2:{s:8:"username";s:5:"admIn";s:8:"password";s:0:"";}
```

现在只要让明文的第29位与32进行异或即可把明文修改为我们想要的admin身份，初始化向量IV只有16位，所以需要修改第一个密文分组的第13位即可改变登录身份。不过在修改了第一个密文分组后，会导致第一个明文分组解密异常，所以还需要控制初始化向量，让他对错误的明文分组进行一些调整，成为正确的明文才可以被服务端正确的解析。

而现在已经有了正确的明文格式：

`a:2:{s:8:"username";s:5:"admIn";s:8:"password";s:0:"";}`，所以大概思路如下：

- 以 admIn 身份登陆，获取到*初始化向量IV*和*密文信息*
- 修改第一个*密文分组*的第13位（与32进行异或，从而改变第二个分组明文中对应字母的大小写）
- 根据服务端返回的错误信息来调整*初始化向量IV*，使第一个分组能被正确解析
- 以调整后的*初始化向量IV*和第二步的密文信息伪造admin身份向服务端发送请求，获取flag

承接着上面的代码：

```python
plain_text = b'a:2:{s:8:"username";s:5:"admIn";s:8:"password";s:0:"";}'
plain_group = re.findall(br'.{16}', plain_text)    # 16个一组进行分组

def xor_bytes(b1, b2):
    """
    两个字节串进行异或操作
    :param b1: 字节串1
    :param b2: 字节串2
    :return: 返回异或后的字节串
    """
    assert isinstance(b1, bytes) and isinstance(b2, bytes) and len(b1) == len(b2)
    ret = bytearray()
    for i in range(len(b1)):
        ret.append(b1[i] ^ b2[i])
    return bytes(ret)


def gen_iv(raw_iv, tips_text, _i=0):
    """
    生成新的iv（修改了当前分组的密文后，在影响下一个分组的明文的同时也会导致当前的分组解密失败，
    所以需要修改前一个分组的密文（或者是初始化向量）
    :param raw_iv: 上一个分组的密文（或初始化向量）
    :param tips_text: 序列化失败返回的明文信息
    :param _i: 第几个分组（0,1,2...)，默认下标为0的分组
    :return: 返回调整后的iv
    """
    assert isinstance(raw_iv, str) and isinstance(tips_text, str)
    raw_iv = base64.b64decode(parse.unquote(raw_iv))
    wrong_text = base64.b64decode(tips_text)    # 解密出错误的明文
    wrong_group = re.findall(br'.{16}', wrong_text)

    _ = xor_bytes(wrong_group[_i], plain_group[_i])   # 错误的明文与正常的明文进行异或

    return parse.quote(base64.b64encode(xor_bytes(raw_iv, _)))


def step2():
    text = deal_send('cipher', 12)
    tips_text = re.findall(r"base64_decode\('(.*?)'\)", text)   # 取出返回的错误明文信息
    assert len(tips_text) > 0
    tips_text = tips_text[0]

    correct_iv = gen_iv(session.cookies['iv'], tips_text)
    replace_cookie('iv', session.cookies, _v=correct_iv)    # 设置iv
    rest = session.get(url, proxies=proxies)
    print(rest.text)


if __name__ == '__main__':
    # step1()
    step2()
```

运行后成功获取到flag
