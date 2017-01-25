# 游戏辅助模块
通过插入内核模块，拦截sys_sendto系统调用，修改发往服务器的数据，实现作弊
(需root权限)

## 功能:
* 三星通关
* 魔王之塔强制通关

## TODO:
* 突破内核模块校验机制，实现在无内核源码的手机上执行

## reference
[kprobes](http://lxr.linux.no/linux+v3.8.2/Documentation/kprobes.txt)
[Linux 内核可装载模块的版本检查机制](http://www.ibm.com/developerworks/cn/linux/l-cn-kernelmodules/index.html)
[突破内核模块版本校验机制](https://yq.aliyun.com/articles/1724)
[Sony L36h Open source archive](http://developer.sonymobile.com/downloads/xperia-open-source-archives/open-source-archive-for-build-10-5-1-a-0-292/)

