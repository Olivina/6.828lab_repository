QEMU=/usr/local/Cellar/qemu/5.1.0/bin/qemu-system-i386 # path to qemu
run:
$(QEMU) -drive file=./kernel.img,index=0,media=disk,format=raw -serial mon:stdio -vga std -smp 1 -drive file=./fs.img,index=1,media=disk,format=raw
