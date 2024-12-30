# 改进的PS签名
支持签名的聚合

## models
PublicParameter负责初始化公共参数

Key中定义了设备密钥的组织形式

KGC负责初始化设备密钥以及TRA密钥

Signature中定义了签名的格式

Device负责定义Device的结构，并对消息进行签名

Verifier负责对签名进行验证，同时负责聚合签名和对聚合签名的验证。

