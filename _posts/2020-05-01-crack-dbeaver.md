---
layout: post
title: 'crack dbeaver'
subtitle: '字节码插桩之破解dbeaver'
tags: 安全 Crack

---

# 前言

`javaagent`是java命令中的一个参数，可以指定一个jar包，当jvm启动时，会先运行该`jar`包中的`premain`方法，从而可以在类加载时修改字节码。像`cat`这种监控工具、`OpenRASP`这种运行时防护工具，都可依赖该技术。而在本文中使用`javaagent`技术来破解一些简单的`java`软件，这里选择的目标应用是`dbeaver`。

`dbeaver`是一个用Java编写的基于Eclipse平台的桌面应用程序，是一个跨平台的数据库管理工具，理论上来说只要有`jdbc`驱动的数据库该工具都可以支持。而目前也已经支持了大量的数据库mysql、mssql、oracle、redis、mongo等。该工具分为开源的社区版和闭源的企业版，相对于商业版来说，社区版支持的数据库种类要少一些，比如 `redis`、`mongodb`这种`noSql`数据库仅在商业版中给予支持。

![image-20220612144841115](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612144841115.png)

# 程序分析

安装后，可以在`dbeaver.ini`中看到启动参数

![image-20220612145917731](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612145917731.png)

我们以java命令启动：

```
java -jar plugins/org.eclipse.equinox.launcher_1.5.600.v20191014-2022.jar
```

![image-20220612150048798](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612150048798.png)

同时命令行中可看到相应的日志，在关闭 `no license found`窗口时，我们可以在日志中看到打印了`No valid license found`后，程序退出

![image-20220612150136395](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612150136395.png)

# Jar包分析

jar的反编译可以使用`jd-gui`，不过我们需要先确定要分析哪些文件，这时可通过搜索关键字来确定一下。类似于jar包、apk这种其压缩格式均为zip，所以我们可以将`plugins`里的jar包全部解压 `find ./ -type f -name '*.jar' -exec unzip -o {} \;`，之后便可以通过`grep`这种基础命令来搜索关键字了。

# Crack

在经过简单的分析后，可锁定一个类 `com.dbeaver.ee.application.EnterpriseWorkbenchWindowAdvisor`

![image-20220612150856379](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612150856379.png)

这里可以很明显的看到，若没有找到`license`，则结束运行。我们可以将这个方法中的校验部分去掉，直接调用`super.postWindowOpen()`来绕过此处限制。若没有其他的暗桩，便可以完成破解。

javaagent的用法网上有很多，这里不再具体说明了，下面贴一下关键代码

```java
public class Agent {
    public static void premain(String args, Instrumentation instrumentation) {
        System.out.println("dbeaver agent load success!");
        instrumentation.addTransformer(new Hook());
    }
}
```

```java

public class Hook implements ClassFileTransformer {
    private static ClassPool classPool = null;

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (classPool == null) {
            classPool = ClassPool.getDefault();
        }
        classPool.insertClassPath(new LoaderClassPath(loader));
        if (className == null || classfileBuffer == null) {
            return classfileBuffer;
        }

        classfileBuffer = hookWorkbench(className, classfileBuffer);
        return classfileBuffer;
    }

    private byte[] hookWorkbench(String className, byte[] classfileBuffer) {
        try {
            className = className.replace("/", ".");
            if (!"com.dbeaver.ee.application.EnterpriseWorkbenchWindowAdvisor".equals(className)) {
                return classfileBuffer;
            }

            System.out.println("[+] hook: " + className);

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(classfileBuffer);
            CtClass ctClass = classPool.makeClass(byteArrayInputStream);
            CtMethod ctMethod = ctClass.getDeclaredMethod("postWindowOpen");
            System.out.println("[+] hook: " + ctMethod.getLongName());

            ctMethod.setBody("{System.out.println(\"[+] hooooooooooooooooooooooooooook\"); super.postWindowOpen();}");

            classfileBuffer = ctClass.toBytecode();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return classfileBuffer;
    }
}
```

打成jar包后，再次尝试 `java -javaagent:agent.jar -jar plugins/org.eclipse.equinox.launcher_1.5.600.v20191014-2022.jar`，可看到，在启动时已经不再展示license窗口了。至此，暴力破解完成。

![image-20220612151841575](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612151841575.png)

# 打印函数调用链

对于`dbeaver`本身来说，在端上并没有做什么比较复杂的防御手段，所以看上去破解起来非常容易。但是对于一些混淆了关键代码、插入各种暗桩的程序，直接这样暴力破解就不是好办法了。这种情况下往往需要进一步的分析其关键逻辑，比如打印关键函数的调用日志来帮助分析，我们这里还是用`dbeaver`做示例。

经过前面的分析，我们大致可以猜到，跟`liscense`可能相关类名中可能会包含`license`或者`jkiss.lm`。我们可以通过如下代码，打印相关类中方法的调用链：

```java
    private byte[] log(String className, byte[] classfileBuffer) {
        className = className.replace("/", ".");
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(classfileBuffer);
            CtClass ctClass = classPool.makeClass(byteArrayInputStream);
            if (ctClass.isAnnotation() || ctClass.isArray() || ctClass.isEnum() || ctClass.isInterface() || ctClass.isKotlin() || ctClass.isFrozen()) {
                return classfileBuffer;
            }
            if (!className.toLowerCase().contains("license") && !className.toLowerCase().contains("jkiss.lm")) {
                return classfileBuffer;
            }

            System.out.println("[+] log to " + className);
            for (CtMethod ctMethod : ctClass.getDeclaredMethods()) {
                if (ctMethod.isEmpty()) {
                    continue;
                }
                ctMethod.insertBefore("System.out.println(\" [++++] " + ctMethod.getLongName() + " \");");
            }
            classfileBuffer = ctClass.toBytecode();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return classfileBuffer;
    }
```

如下记录中，我们也可也看到其校验`license`的过程，不过因为破解算法不是本文的目的，这里就不再继续分析其算法了。

![image-20220612153122273](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612153122273.png)

![image-20220612153627215](/assets/img/md/2020-05-01-crack-dbeaver.assets/image-20220612153627215.png)

**注：本文仅供技术学习，不提倡且不提供破解工具**

# 参考

>  https://zh.wikipedia.org/wiki/DBeaver
>
> https://www.cnblogs.com/rickiyang/p/11368932.html