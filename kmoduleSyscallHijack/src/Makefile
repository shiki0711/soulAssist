KDIR = $(L36H_KERNEL)

EXTRA_CFLAGS += -fno-pic

obj-m += hook.o

hook-objs := main.o proc.o hook_config.o hook_send.o base64.o dbg.o

all:
	make -C $(KDIR) M=$(PWD) modules
	tar czf hook.tar.gz hook.ko wrapper/soulAssistKmoduleWrapperL36H.sh
	echo yanfeng | sudo -S cp -a hook.tar.gz /media/sf_shared/

clean:
	make -C $(KDIR)  M=$(PWD) clean
	rm -rf hook.tar.gz

