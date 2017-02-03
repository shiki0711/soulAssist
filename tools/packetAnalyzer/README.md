# 游戏数据包解码脚本(适用于1.6.3版本)

## 系统需求
* OS: Linux/OSX(Windows平台可以使用MinGW shell执行)
* Python 2.7.x
* Openssl

## 使用方法
1. 将笔记本电脑设定为wifi热点，并在笔记本电脑上运行wireshark
2. 将手机连接到笔记本电脑的wifi热点
3. 运行游戏
4. 在wireshark中找到游戏对应的数据包  
   (数据包特征为TCP[PSH, ACK]，Data第12字节处开始连续64个字节为base64编码)
5. 拷贝Data域内容到"pkt.txt"并保存到script目录  
   (拷贝的数据格式为字符串表示的16进制数据，参见script/sample.txt)
6. 在命令行输入(Window可以使用MinGW shell):
```
$ cd script
$ ./dump_packet.sh -s sample.txt
```
发送至服务器的数据包使用-s选项，从服务器接收的数据包使用-r选项，从服务器接收的聊天信息使用-c选项  

## 数据包构造说明
```
------------------------------------------------------------------
|TCP/IP header|L   |T   |KEYL|KEY |IVL |IV  |(PAD)|DATL|DAT |SUM |
------------------------------------------------------------------
```

|字段|长度|格式|模式(发送S/接收R)|内容|
|----|----|--------|--------|----------------|
|L|4byte|int(little endian)|SR|整个数据包的长度
|T|4byte|int(little endian)|SR|消息类型码，用于区分消息类型
|KEYL|4byte|int(little endian)|SR|KEY字段长度，固定为64
|KEY|64byte|base64 string|SR|解密DAT字段用的密钥
|IVL|4byte|int(little endian)|SR|IV字段长度，固定为44
|IV|44byte|base64 string|SR|解密DAT字段用的向量
|PAD|4byte|int(little endian)|R|仅存在于接收数据包，意义不明
|DATL|4byte|int(little endian)|SR|DAT字段长度
|DAT|变长|base64 string|SR|数据包内容
|SUM|4byte|int(little endian)|SR|校验和，值为前述所有字段每个字节的和

其中，DAT字段是使用由游戏客户端随机产生的密钥Rkey/Riv进行aes-cbc加密后base64编码而来  
KEY和IV字段是游戏客户端使用固定主密钥进行aes-cbc加密后base64编码而来  
解码时先使用固定主密钥对KEY和IV进行解码得到Rkey和Riv，再使用Rkey和Riv对数据包进行解码

## TODO
* 将脚本改写为wireshark插件，以便在wireshark直接观察其内容
