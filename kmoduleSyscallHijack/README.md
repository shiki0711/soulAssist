# 游戏辅助模块

## 使用方法：
* [编译程序](#compile)
* 将hook.tar.gz传送至手机并解压
```
$ adb push hook.tar.gz /mnt/sdcard/
$ adb shell
$ cd /mnt/sdcard/
$ tar xzf hook.tar.gz
```
* 拷贝wrapper文件夹下脚本到/system/bin/文件夹下并添加执行权限(以L36H为例)
```
# cp -a wrapper/soulAssistKmoduleWrapperL36H.sh /system/bin/
# chmod 777 /system/bin/soulAssistKmoduleWrapperL36H.sh
```
* 启动游戏
* 执行wrapper脚本开启作弊
```
# #加载辅助模块
# soulAssistKmoduleWrapperL36H.sh -l -s
# 
# #设置普通副本通关时间(三星通关)，时间范围10-99(秒)
# soulAssistKmoduleWrapperL36H.sh -t time
# 
# #设置魔王之塔强制通关
# soulAssistKmoduleWrapperL36H.sh -r
# 
# #停止辅助模块
# soulAssistKmoduleWrapperL36H.sh -f -u
```
(手机需root并安装busybox)

## 功能:
* 三星通关
* 魔王之塔强制通关

## 支持机型:
* Sony L36H

## TODO:
* ~~修改次元之门哥布林掉落为100%掉落红宝石碎片~~
* ~~修改扭曲地下城掉咯碎片数量~~
* 魔王之塔通关时间修改(防服务器检测)
* 普通地下城强制通关。即使战斗失败，也能够成功通关。
* 竞技场强制获胜。即使挑战失败，也能够取得胜利。
* 扭曲地下城强制通关。即使战斗失败，也能够成功通关。
* 突破内核模块校验机制，实现在无对应内核源码的手机上运行

<h2 id="compile">编译程序</h2>

* 配置编译环境(build-essential、交叉编译器等)
* 下载解压对应手机内核的源码
* 编辑.export文件，配置交叉编译器和内核源码树路径
* 执行  

```
$ source .export
```
* 编译内核
```
$ make menuconfig
$ make
```
* 编译程序
```
$ make
```

## reference
* [kprobes](http://lxr.linux.no/linux+v3.8.2/Documentation/kprobes.txt)  
* [Linux 内核可装载模块的版本检查机制](http://www.ibm.com/developerworks/cn/linux/l-cn-kernelmodules/index.html)  
* [突破内核模块版本校验机制](https://yq.aliyun.com/articles/1724)  
* [Sony L36h Open source archive](http://developer.sonymobile.com/downloads/xperia-open-source-archives/open-source-archive-for-build-10-5-1-a-0-292/)
