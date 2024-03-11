#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs none /sys/kernel/debug

cat <<!


Boot took $(cut -d' ' -f1 /proc/uptime) seconds


 ________                    __                 
/        |                  /  |                
########/__    __   _______ ## |____    ______  
   ## | /  |  /  | /       |##      \  /      \ 
   ## | ## |  ## |/#######/ #######  |/######  |
   ## | ## |  ## |## |      ## |  ## |##    ## |
   ## | ## \__## |## \_____ ## |  ## |########/ 
   ## | ##    ## |##       |## |  ## |##       |
   ##/   ####### | #######/ ##/   ##/  #######/ 
        /  \__## |                              
        ##    ##/                               
         ######/                                


Welcome to Tyche


!

# Open a shell if switch root fail
error() {
    echo "Failed to switch root to Ubuntu"
    exec /bin/sh
}

error_part3() {
  echo "Failed to mount"
  umount /newroot
}
##
### Install disk
mknod /dev/nvme0n1p6 b 259 6
###
#### Create new root
mkdir /newroot
mount /dev/nvme0n1p6 /newroot || error_part3
ls /newroot/sbin || error_part3
###
#### Switch root
exec switch_root /newroot /sbin/init || error

exec /bin/sh
