对安全等级分别为 80, 112, 128 的协议具体实现。

### 80-bit 安全等级

这个安全等级对应表中的 Legacy (遗留) 标准，具体参数如下：

对称加密算法 (Symmetric Algorithm): 2TDEA (双密钥 3DES) CBC Mode

椭圆曲线 (Elliptic Curve): 160-bit

哈希函数 (Hash): SHA-1

### 从 80-bit 提升到 112-bit

根据表格，112-bit 安全等级对应的参数如下：

对称加密算法 (Symmetric Algorithm): AES-128 (或 3TDEA) CBC Mode

椭圆曲线 (Elliptic Curve): 224-bit

哈希函数 (Hash): SHA-224

选择 AES-128 作为对称加密算法

### 从 112-bit 升级到 128-bit

128-bit 安全等级对应的参数如下：

对称加密算法 (Symmetric Algorithm): AES-128 CBC Mode

椭圆曲线 (Elliptic Curve): 256-bit

哈希函数 (Hash): SHA-256