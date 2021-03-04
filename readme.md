# 协议设计


## 请求连接

为了避免重放攻击，每个接入的端口用一个不同公钥和私钥对。

私钥 = blake3::hash(seed+ip+端口)

因为从私钥计算公钥比较耗时，所以会进行缓存。

---

为了避免UDP放大攻击，连接建立之前(服务器第一次给客户端发数据)，服务器发的包比客户端发的包要小。

参考：[盘点：常见UDP反射放大攻击的类型与防护措施](https://zhuanlan.zhihu.com/p/83793355)

---

响应空包表示还活着，但是得重新连接（可能是密钥变了），也可以用来做生日攻击的udp端口探测

---

身份公钥 ed25519

seahash 种子

连接公钥 x25519

---

客户端 : ping 协议版本号 客户端时间 服务器端口 服务器IP
         1 + 2 + 8 + 2 + 4 = 17

服务器 : pong 服务器端时间 seahash(服务器端时间+客户端IP+客户端端口+seed)
         1 + 8 + 8 = 17

客户端 : 如果没有缓存(缓存时间16秒)中没有请求此IP和端口，放弃 
         
  ping 连接公钥 服务器端时间 服务器返回的seahash 签名 身份公钥 杂凑token
 
  1 + 32 + 8 + 8 + 64 + 32

  其中 签名 的内容为 连接公钥 服务器端时间 服务器返回的seahash
  
  使得 seahash(连接公钥 服务器端时间 服务器返回的seahash 身份公钥 签名 杂凑token) 开头有18个0
   1+32+64+32+8+8+???

服务器 : 如果 时间 > 9 丢弃，如果签名不对，丢弃
         pong 连接公钥 aes-256-gcm加密(身份公钥+身份公钥对客户端连接公钥签名) 
         1+32
          解密后 8+64

客户端 : 如果没有缓存(缓存时间9秒)中没有请求此IP和端口，放弃

---

打洞连接流程
upnp

请求节点，返回异或距离相等的，然后继续请求，返回异或距离相等的，直到所有节点返回的都为已有的

1. A尝试直接连接新节点B，如果能连接成功，记录到数据库，方便以后用(数据库表设计，节点连接公钥、最后连接成功时间)
2. 3秒没响应，向服务器C请求，服务器告知新节点，新节点给A发空UDP包，A等待3秒后重新请求B


---

## 记录


异或距离 - ip list

有新请求，如果 ip list 长度不超过 32 ，那么添加这个ip和端口

如果 ip list 长度超过 16，那么就pop第一个测试是否能连通，如果能连通，就放到最后，如果不行，就丢弃, 在最后插入新的

Rust 标准库学习：VecDeque https://zhuanlan.zhihu.com/p/69091605


---


异或距离 - 最后活跃时间 - IP - 端口 - 首次活跃时间

where 异或距离=异或距离 and 最后活跃时间+60>当前时间 order by 首次活跃时间

公钥 - IP - 端口 - 最后活跃时间

距离 - 公钥

IP 端口 公钥 最后活跃时间 是否是外网端口


最后一条消息的时间戳 最后一条消息的内容

身份公钥

IP
端口
连接密钥
最后一次心跳的时间 （每20秒跳一次）
能否从随机端口访问

IP端口 - 最后响应时间 

对方公钥和自己公钥的距离

距离
  最后响应时间
    IP:端口

不断请求，连接更自己更近的节点


---

有2个K桶，一个是内网，一个是公网。内网K桶可用用来辅助打洞。



