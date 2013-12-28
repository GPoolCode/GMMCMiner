
Please mine at http://mmc.gpool.net

If you like the pool, please donate MMC to address M9PrLnpQamdxBY1E6NCQ1SmkHXyXu1iyQm

# How to install on Ubuntu

sudo apt-get install libqt4-dev

sudo apt-get install libssl-dev

make

For other version of Linux, please try to install similar packages ( libqt4-devel, libssl-devel ).

If there is still something wrong with "make", try "qmake" first, then try "make"

# Usage

mmcminer -h IP -p PORT -u ADDRESS -t THREAD

The miner will use approximately 1GB memory.

# Ubuntu下安装方法 

sudo apt-get install libqt4-dev

sudo apt-get install libssl-dev

make

其他版本Linux安装类似的软件包，安装后如果还有问题，试试先执行qmake，再执行make

Centos下可能是 libqt4-devel 和 libssl-devel

# 命令行参数

mmcminer -h IP地址 -p 端口 -u 钱包地址 -t 线程数

程序大约占用1GB内存。
