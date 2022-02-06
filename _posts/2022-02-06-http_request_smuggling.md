---
layout: post
title: 'http request smuggling'
subtitle: 'HTTP请求走私研究'
tags: 安全 web
---

# 1. 请求走私简介

HTTP请求走私上2005年提出的一个攻击技术，利用 在 Client 与 Server 之间各种Http设备对非标准HTTP协议的不同解释（重点是请求体长度）而进行的一种攻击。可用于绕过WAF、毒害HTTP缓存、向其他用户注入恶意响应包、劫持用户请求等。而HTTP2的出现也带来了一些新的攻击面。

![714321381f973a07d19c69ee6e022be4.png](/assets/img/md/2022-02-06-http_request_smuggling/714321381f973a07d19c69ee6e022be4.png)

# 2. 基础请求走私

示意图：

![b2ee796f8498340930053c711058e64a.png](/assets/img/md/2022-02-06-http_request_smuggling/b2ee796f8498340930053c711058e64a.png)

## 2.1 CL - TE 走私

攻击原理：

攻击者在一个请求中传入 Content-Length 以及 Transfer-Encoding，Front End 优先取 Content-Length，Back End 优先取 Transfer-Encoding。

攻击请求如下：

Content-Length 传入正确的长度，Front End会将整个请求传入 Back End。Transfer-Encoding长度为0，Back End直接截取，后续的请求体当作新请求处理。当普通用户（也就是受害者）的请求过来时，包含用户的请求头在内的整个请求即可作为恶意请求的请求体处理。此时如下的利用，攻击者可将用户的认证信息拼接至自己的评论留言中：

![49aa5511e04bc3947794672b34955a49.png](/assets/img/md/2022-02-06-http_request_smuggling/49aa5511e04bc3947794672b34955a49.png)

![20b3f32473686e6beb943c23693a1fa8.png](/assets/img/md/2022-02-06-http_request_smuggling/20b3f32473686e6beb943c23693a1fa8.png)

## 2.2 TE - CL 走私

攻击原理：

攻击者在一个请求中传入 Content-Length 以及 Transfer-Encoding。Front End 优先取 Transfer-Encoding，Back End优先识别 Content-Length。

坑点：

- Transfer-Encoding中，chunk 的长度需要用16进制表示。
- 注意计算长度时的换行为 回车换行，两个字符

攻击请求如下：

FrontEnd以 Transfer-Encoding 优先，将整个请求穿入BackEnd。BackEnd 以 Content-Length 优先，截止到 第二个红框中的 POST 前。后续的body视为新的请求，body中的 `Content-Length`为攻击者构造的第二个请求的长度，设置为500，可处原本的body外，再包含普通用户的请求信息。如下，将普通用户的认证信息拼接至自己的评论留言中：

![d6eac425552f64fa3f9a4e31eb3ee745.png](/assets/img/md/2022-02-06-http_request_smuggling/d6eac425552f64fa3f9a4e31eb3ee745.png)

![90fb2b630c2195ffc727530c05a0e4c1.png](/assets/img/md/2022-02-06-http_request_smuggling/90fb2b630c2195ffc727530c05a0e4c1.png)

## 2.3 非标准TE头

一般情况下，Front-End 与 Back-End 都支持 Transfer-Encoding 头，但要知道，不同服务器对非法协议、解析顺序的处理不同。所以可以通过一些细微的修改 Transfer-Encoding ，使前后端只有一个服务器解析该字段，实现相应的利用。例如：

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

攻击示例：

Front-End 取第一个 Transfer-Encoding 字段，可以正常解析。Back-End 取第二个Transfer-Encoding 字段，无法识别，取Content-Length，默认长度为0。实现请求走私

![27263d3ad8d7655cd0ed4a23da00bb3e.png](/assets/img/md/2022-02-06-http_request_smuggling/27263d3ad8d7655cd0ed4a23da00bb3e.png) 

![6e7dcf70f60b3d4fd7bc73cdc79b752b.png](/assets/img/md/2022-02-06-http_request_smuggling/6e7dcf70f60b3d4fd7bc73cdc79b752b.png)

## 2.4 非标准换行符

在HTTP的标准语法中，换行符为 `\r\n`，但是如果 `Front-End`与`Back-End`在对单个`\n`符号的处理中存在差异的话，也可能会导致请求走私攻击。


# 3. 常见攻击点

https://portswigger.net/web-security/request-smuggling/exploiting

https://portswigger.net/web-security/request-smuggling/advanced

## 3.1. 绕过 Front-End 的安全限制

场景：Front-End 中会进行访问控制，未认证的用户或普通用户仅可访问到部分URL。如 `/Home`，而无法直接访问到 类似`/Admin`的管理界面。这时便可利用请求走私的缺陷，绕过此安全限制。示意如下：

![db987852b11a66dd8c146046f2c9f277.png](/assets/img/md/2022-02-06-http_request_smuggling/db987852b11a66dd8c146046f2c9f277.png)

对于 Front-End 来说，是两个请求，都是 `/home`。对于 Back-End 来说，第二个请求是 `/admin`，这样通过 `CL-TE`请求走私漏洞，实现安全限制的绕过。（`TE-CL`类似）

例：`https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te`

目标，访问到 `/admin`页面。正常访问时，无权限：

![b7e5d0a4d579a464ff4f9fefabc9d151.png](/assets/img/md/2022-02-06-http_request_smuggling/b7e5d0a4d579a464ff4f9fefabc9d151.png)

走私请求`/admin`资源:

![8ac5cd15de5375215df3317c9004aeee.png](/assets/img/md/2022-02-06-http_request_smuggling/8ac5cd15de5375215df3317c9004aeee.png)

再次发送一个正常请求，Back-End将其与上一个请求中的 `GET /admin`合并，从而返回`/admin`下的资源：

![79d75eed2d2adefb21b905d79c6a1403.png](/assets/img/md/2022-02-06-http_request_smuggling/79d75eed2d2adefb21b905d79c6a1403.png)

## 3.2. 窃取请求

可进一步划分：

- 窃取 Front-End 的请求重写部分
- 窃取其他用户的请求（如窃取他人的cookie）

下面以 “窃取 Front-End 的请求重写部分”进行示意：

场景：请求传到 Back-End 前，Front-End 会在请求中重写一些字段。如当前用户的 userId、X-Real-Ip 等

通常的利用方式：

1. 找到一个可以将请求参数回显的接口。（如发布帖子、编辑个人信息等接口）
2. 将该参数调整为最后一个参数
3. 请求走私，让后续的一个正常请求作为参数，回显出来

如下：

![97bfcf034a731af8c312a1b850cb6ebd.png](/assets/img/md/2022-02-06-http_request_smuggling/97bfcf034a731af8c312a1b850cb6ebd.png)

如下的攻击示例:`https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting`

走私了一个评论帖子的请求，红框处设置对应请求的`Content-Length`以及`comment`字段（普通用户的请求会拼到这个字段中）

![8885ebbae0a700cf604e848b791c7b73.png](/assets/img/md/2022-02-06-http_request_smuggling/8885ebbae0a700cf604e848b791c7b73.png)

从响应内容中可以看到用户的正常请求已变成了评论成功的响应：

![e362edbab489107a7a9bbda57b527a50.png](/assets/img/md/2022-02-06-http_request_smuggling/e362edbab489107a7a9bbda57b527a50.png)

这里也可以看到 Front-End 定制的字段（X-lWocph-Ip）：

![55ba87668feacbbeffc31a068548aa5b.png](/assets/img/md/2022-02-06-http_request_smuggling/55ba87668feacbbeffc31a068548aa5b.png)

## 3.3. 进一步利用反射XSS

相对于一般的反射XSS，请求走私后的反射XSS有如下两个特点：

- 不再需要诱导受害者主动打开恶意链接
- 可以利用请求中的其他部分来进行XSS攻击，例如 `User-Agent: <script>alert(1)</script>`

如下示例：

![33dcdae4c0b93c682614add35f8a44bb.png](/assets/img/md/2022-02-06-http_request_smuggling/33dcdae4c0b93c682614add35f8a44bb.png)

## 3.4. 缓存毒化

攻击示意如下，绿色部分为要毒化的正常js请求。因为存在请求走私，Back-End返回`/home`下的内容作为原本的`js`资源。缓存服务器进行缓存，实现缓存毒化攻击。

![f2aa0f5f547983c155e8aee5709c1135.png](/assets/img/md/2022-02-06-http_request_smuggling/f2aa0f5f547983c155e8aee5709c1135.png)

例，如下为正常的js资源，会被缓存30s：

![01abbec17f817578e72217efbf4592d2.png](/assets/img/md/2022-02-06-http_request_smuggling/01abbec17f817578e72217efbf4592d2.png)

利用请求走私漏洞来毒化缓存：

![517d6667b9ac611865bf04963b374441.png](/assets/img/md/2022-02-06-http_request_smuggling/517d6667b9ac611865bf04963b374441.png)

![703cfd087441571bd575e99367e6b73f.png](/assets/img/md/2022-02-06-http_request_smuggling/703cfd087441571bd575e99367e6b73f.png)

## 3.5. 缓存欺骗

与缓存毒化名称有些相似，但原理不同：

- 缓存毒化是攻击者在缓存服务器缓存上恶意内容，影响到普通用户的正常访问
- 缓存欺骗是攻击者设法让缓存服务器缓存上普通用户的敏感信息，从而窃取该用户的信息

如下的 CL-TE 请求走私漏洞利用：

![d3240ca00bdfff5052b721efbdeab5e9.png](/assets/img/md/2022-02-06-http_request_smuggling/d3240ca00bdfff5052b721efbdeab5e9.png)

当正常用户访问静态资源时，所发出的请求被应用服务器当作：

![09a8c1057f41c5f1ae002d87f4ddbfd0.png](/assets/img/md/2022-02-06-http_request_smuggling/09a8c1057f41c5f1ae002d87f4ddbfd0.png)

缓存服务器将该用户的 `/private/messages`信息 缓存至 `/static/some-image.png`中。攻击者访问 `/static/some-image.png`即可窃取用户的敏感信息。

## 3.6 响应队列毒化

它的原理是走私一个完整的请求，使 Back-End 返回两个响应，而 Front-End 仅期待一个相应。从而导致后续的所有请求的处理全部乱序。

想要实现此攻击，需要满足以下条件：

1. Front-End 与 Back-End 之间的tcp连接需可重复用于多个请求/响应周期
2. 攻击者需要走私一个完整的请求
3. 攻击不会导致任何一台服务器关闭TCP连接

示意：

![dafb49f299261bcb7163314315793e24.png](/assets/img/md/2022-02-06-http_request_smuggling/dafb49f299261bcb7163314315793e24.png)

# 4. HTTP2 下的请求走私

检测站点是否支持 `http2`：

```shell
curl -v --http2 --http2-prior-knowledge https://www.baidu.com
```

HTTP2现有的实现提高了性能及安全性的同时，也带来了新的攻击面。如原本请求走私安全的系统在支持HTTP2后可能会导致存在漏洞，另外即便 Front-End 与 Back-End 之间没有重用连接，也可以使用HTTP2来实现高级的攻击。

主要依靠的有两点：

1. HTTP2的请求长度标识
	HTTP2的请求长度不再像之前的 Content-Length 一样，作为一个独立的字段表示。而是在每个“frames”前有一个显式的长度表示。因为不存在解释差异了，所以这种设计很好的避免了请求走私这种攻击。
2. 请求降级
	HTTP2的请求降级指的是 Front-End 以HTTP1的语法重写原本的HTTP2请求，生成等效的HTTP1请求传给 Back-End。这种做法就会带来相应的安全隐患。

![6ff6322b57e8dd7fd9977adcf330c164.png](/assets/img/md/2022-02-06-http_request_smuggling/6ff6322b57e8dd7fd9977adcf330c164.png)

需注意，Burp的 2021.9.1 版本之前有bug，对于不支持 ALPN 的HTTP2站点，无法强制进行HTTP2通信。对于 2021.9.1 及其之后的站点，通过勾选 Allow HTTP/2 ALPN override 来忽略 ALPN，直接HTTP2通信。（ALPN为 SSL层的协议协商功能，也就是在 SSL 层协商应用层要使用的协议是 HTTP1.1 还是 HTTP2 还是其他）

![39a8e891eec9816afdbae8f71644b5b4.png](/assets/img/md/2022-02-06-http_request_smuggling/39a8e891eec9816afdbae8f71644b5b4.png)

## 4.1 H2.CL、H2.TE 走私

对于 HTTP/2 来说，不再需要使用 Content-Length 标识请求体长度。但是 Content-length 仍然被允许。进行如下请求

![840963938795b3f6ac15a1ab8bc272e3.png](/assets/img/md/2022-02-06-http_request_smuggling/840963938795b3f6ac15a1ab8bc272e3.png)

Front-End 将该 HTTP/2 请求降级为 HTTP/1.1 后，传给 Back-End，但对 Back-End 来说，是两个请求：

![6fdfb9b6769b4365edf39dfc94625600.png](/assets/img/md/2022-02-06-http_request_smuggling/6fdfb9b6769b4365edf39dfc94625600.png)

类似的，H2.TE 也是类似的情况：

![d785fd55c98661acf5eaf9ba4bc1c7f8.png](/assets/img/md/2022-02-06-http_request_smuggling/d785fd55c98661acf5eaf9ba4bc1c7f8.png)

利用时，也可以直接重定向到自己的站点，如下：

![3689beccaa3a976687f9c31535fcec59.png](/assets/img/md/2022-02-06-http_request_smuggling/3689beccaa3a976687f9c31535fcec59.png)

## 4.2 CRLF 注入走私

不同于 HTTP1 的 `\r\n`作为头之间的分隔符，HTTP2的传输方式不再依赖于此。也就是说在HTTP2中，`\r\n`不再具有特殊含义，可以作为普通值出现在字段中。

如下：

![a8c05e1b2de4ab85d0caae8d1769d11b.png](/assets/img/md/2022-02-06-http_request_smuggling/a8c05e1b2de4ab85d0caae8d1769d11b.png)

若只看HTTP2这种写法也不会带来安全问题，但当它被重写为HTTP1请求时，`\r\n`若被直接解析，会导致之后传给Back-End的HTTP1请求中，存在头 `Transfer-Encoding: chunked`。这种解析上的差异性，将会带来相应的安全隐患。

攻击演示如下，右侧红框中，使用`\r\n`(在burp中使用Shfit + Enter来插入 \r\n字符)注入头 `Transfer-Encoding: chunked`。进行请求走私攻击。左侧要走私的请求是提交评论的请求。

![0102dcac973a10a1f89e56af52bcefd8.png](/assets/img/md/2022-02-06-http_request_smuggling/0102dcac973a10a1f89e56af52bcefd8.png)

普通用户在发起请求时，会拼接到攻击者所指定的“提交评论”请求中，从而获取该用户的cookie。如下：

![05e7fe7a77434fe0d4f386fe168d553e.png](/assets/img/md/2022-02-06-http_request_smuggling/05e7fe7a77434fe0d4f386fe168d553e.png)

## 4.3 CRLF注入毒化响应队列

与2.2有些类似，在单个请求头中注入 `\r\n`，使其降级时被拆分为多个请求。攻击示意如下：

![284565d289b4dd7f319f13e140502464.png](/assets/img/md/2022-02-06-http_request_smuggling/284565d289b4dd7f319f13e140502464.png)

例：https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection

利用 CLRF问题，毒化响应队列。从而窃取到其他用户的响应包：

![3a81f12a2c8eda30817ffebc4ef77383.png](/assets/img/md/2022-02-06-http_request_smuggling/3a81f12a2c8eda30817ffebc4ef77383.png)

## 4.4 构造请求隧道泄露内部头信息

对于 Front-End 到 Back-End 之间的连接不重用的情况（甚至用户的每个请求都对应着一个 Front-End 到 Back-End 的新的连接），可通过请求隧道(Request Tunnelling)进行攻击，窃取内部头信息。

**请求隧道**：Front-End 读取 Back-End 返回的所有数据，示意如下：

![3a90cbe976bdeb4aa1b42abeb98234cc.png](/assets/img/md/2022-02-06-http_request_smuggling/3a90cbe976bdeb4aa1b42abeb98234cc.png)

攻击示例如下：

![63f0e99f6808d7f6f087a906e02b7ebd.png](/assets/img/md/2022-02-06-http_request_smuggling/63f0e99f6808d7f6f087a906e02b7ebd.png)

当 Front-End 填充内部头信息时，追加到 `comment=`后传给 `Back-End`，走私一个完整的请求，攻击者也可通过提交的内容得到 Front-End所填充的内部头信息。

## 4.5 “盲”请求隧道 To “非盲”

**“盲”请求隧道**：相对于 4.4 中的请求隧道中的示意图，有一类 Front-End 只会返回合法的数据给到用户，（虽然 Back-End 返回了两个请求，但 Front-End 根据 响应包中的Content-Length 字段来返回正常的响应给到用户）。示意如下：

![19cb02d1dbedbbfb64282c11665b0d75.png](/assets/img/md/2022-02-06-http_request_smuggling/19cb02d1dbedbbfb64282c11665b0d75.png)

不过我们仍然可通过一定的手段，将“盲”请求隧道转为正常的请求隧道。

例如，使用 HEAD 请求：

HEAD方法的响应通常会包含 Content-Length，不过它所表示的意思是对应 GET 方法所能获取到的响应体长度，而 HEAD方法的响应一般来说是没有响应体的。若 Front-End 没有进行相应的判断，就可以利用 HEAD 方法，来将 “盲”请求隧道 转换为 “非盲”隧道。

![f9d5ca547554b729a7277f0e4592f27f.png](/assets/img/md/2022-02-06-http_request_smuggling/f9d5ca547554b729a7277f0e4592f27f.png)

如下示例，通过HEAD方法所对应的响应中 Content-Length 为7720，可走私掉下个响应中的内容。

![3ecd732e2f339071927144a2ff9f483f.png](/assets/img/md/2022-02-06-http_request_smuggling/3ecd732e2f339071927144a2ff9f483f.png)

靶机：https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling

攻击所使用的请求如下，可看到存在一个 search 参数可回显。

![1f5ca9aaca80f8ec188235584d1d6464.png](/assets/img/md/2022-02-06-http_request_smuggling/1f5ca9aaca80f8ec188235584d1d6464.png)

通过CLRF注入实现请求走私，构造恶意Header字段，从而将 Front-End 后续追加的字段回显出来。发送请求，可看到 Front-End 再重设请求时自定义的一些字段信息，如`X-SSL-VERIFIED、X-SSL-CLIENT-CN X-FRONTEND-KEY`等：

![1c32b31470e5e4eea321e5e5a9b83315.png](/assets/img/md/2022-02-06-http_request_smuggling/1c32b31470e5e4eea321e5e5a9b83315.png)

直接修改这几个字段后，走私该请求，至此成功访问到 `/admin`页面：

![50d5569bc94a1cdefb46557e2dccb5a9.png](/assets/img/md/2022-02-06-http_request_smuggling/50d5569bc94a1cdefb46557e2dccb5a9.png)

## 4.6 构造请求隧道实现缓存毒化

原理与 HTTP1 下的请求走私缓存毒化类似，通过 构造的请求隧道，让原本应该返回JS的Back-End，返回攻击者控制的恶意内容，Front-End（缓存服务器）将其缓存下来。

示意如下，攻击path参数：

![2b77f89738df417bb14338b325e23629.png](/assets/img/md/2022-02-06-http_request_smuggling/2b77f89738df417bb14338b325e23629.png)


# 5. 请求走私检测方案

## 5.1 计时检测

检测请求走私最有效的方式就是发送可以导致服务器超时的请求，通过时间延迟的方式进行检测。Burpsuite Scanner中集成了此方法。

**检测 CL.TE 走私漏洞**

若存在 CL.TE 走私漏洞，则如下请求可造成服务端超时。Front-End 接收 Content-Length，认为长度为4，则忽略后续的 X 字符。Back-End 接收 Transfer-Encoding，第一块（1字符）接收完后，等待后续字符，导致超时。

若不存在漏洞，使用 Content-Length 的话正常的接收请求，使用 Transfer-Encoding 的话，X为错误的块大小，直接返回错误请求（部分服务器遇到这种错误块时也会卡住，所以还可以拼接为正常的块请求）。

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X   // 这里应该是一个新块的大小（十六进制），传入X会导致非法请求，正常应该返回错误的请求
```

**检测 TE.CL 走私漏洞**

若存在 TE.CL 走私漏洞，如下请求可造成服务端超时。Front-End 接收 Transfer-Encoding: chunked ，只返回部分请求体给到 Back-End（不返回X）。而 Back-End 使用 CL，期望收到更多的字节，这就导致了超时。（若存在 CL.TE 漏洞，这种检验方式会干扰到正常用户，所以建议先进行 CL.TE 漏洞的检测，不存在再检查 TE.CL 漏洞）


```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0


X
```

## 5.2 通过不同响应来检测

这种方式会干扰到正常用户，一般不推荐。

如下请求为正常请求：

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

q=smuggling&x=
```

**CL.TE漏洞检测**

如下，Front-End 使用 Content-Length，接收全部的请求体。Back-End使用Transfer-Encoding，第一个请求截止在 X 前。X分给第二个请求，导致后续的正常请求方法变为 `XPOST` 或 `XGET`等，导致第二个请求失败

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Transfer-Encoding: chunked

e
q=smuggling&x=
0

X
```

**TE.CL漏洞检测**

如下请求，若存在漏洞，Front-End传输全部的请求，Back-End取 Content-Length，剩余的 X 字符及之后的内容作为第二个请求部分。当用户正常访问，第二个请求为非法请求，导致请求失败。

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

1
X
0


```

## 5.3 通过走私完整请求检测

可以走私一个完整请求，查看是否会获得两个响应。

![39c3b49b99bd151c315e8285e1329244.png](/assets/img/md/2022-02-06-http_request_smuggling/39c3b49b99bd151c315e8285e1329244.png)   ![e9ad9fe07d471727041954ac0c7aa3ee.png](/assets/img/md/2022-02-06-http_request_smuggling/e9ad9fe07d471727041954ac0c7aa3ee.png)

不过这个判断并不准，连接多个响应正是 HTTP/1.1 的工作方式。不过对 HTTP2来说，如果能在响应包里看到 HTTP/1.1 ，则说明存在请求走私问题。

参考 4.5 中的“盲”请求隧道问题，有些 Front-End 在收到 完整的响应包后，会终止当前连接，所以还可以借助 HEAD 方法来走私完整请求，进行相对完善的检测。

# 6. 连接不重用问题

在一些 Front End 中，每个 Client 都是单独的连接到 Back End 中，这样会给漏洞利用带来极大的挑战，如下所示：

![d749ff2a6fb0fb0b8438210e223e07fc.png](/assets/img/md/2022-02-06-http_request_smuggling/d749ff2a6fb0fb0b8438210e223e07fc.png)

此时虽无法干预到其他用户的请求，但可以尝试 毒化缓存、构造请求隧道泄露内部头信息、伪造内部头信息 等操作，参考 4.4-4.6。

# 7. 其余请求走私

未完，待续...

https://www.intruder.io/research/practical-http-header-smuggling

# 8. HTTP2明文走私

https://bishopfox.com/blog/h2c-smuggling-request


# 9. 参考

> [Http Request Smuggling In 2020 - New Variants, New Defenses and New Challenges](https://www.blackhat.com/us-20/briefings/schedule/#http-request-smuggling-in---new-variants-new-defenses-and-new-challenges-20019)
> [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
> [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2#request)
> [请求走私-测试环境](https://portswigger.net/web-security/request-smuggling)
> [请求走私-实验参考](https://paper.seebug.org/1048/#511-cl-te)