# 游戏辅助模块

## 使用方法：
1. 编译模块
2. 将hook.tar.gz传送至手机并解压
3. 拷贝wrapper文件夹下脚本到/system/bin/文件夹下并添加执行权限
4. 执行wrapper脚本开启作弊  
(手机需root并安装busybox)

## 功能:
* 三星通关
* 魔王之塔强制通关

## 支持机型:
* Sony L36H

## TODO:
* ~~修改次元之门哥布林掉落为100%掉落红宝石碎片~~
* 魔王之塔通关时间修改(防服务器检测)
* 突破内核模块校验机制，实现在无对应内核源码的手机上运行

## reference
* [kprobes](http://lxr.linux.no/linux+v3.8.2/Documentation/kprobes.txt)  
* [Linux 内核可装载模块的版本检查机制](http://www.ibm.com/developerworks/cn/linux/l-cn-kernelmodules/index.html)  
* [突破内核模块版本校验机制](https://yq.aliyun.com/articles/1724)  
* [Sony L36h Open source archive](http://developer.sonymobile.com/downloads/xperia-open-source-archives/open-source-archive-for-build-10-5-1-a-0-292/)


