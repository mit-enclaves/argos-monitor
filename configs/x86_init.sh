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

# When running on the CI set this to true
runs_on_ci=false

if [ "$runs_on_ci" = true ] ; then
    echo "Powering off!"
    poweroff -f
    echo "Failed to poweroff"

    exec /bin/sh
fi

# Open a shell if switch root fail
error() {
    echo "Failed to switch root to Ubuntu"
    exec /bin/sh
}

# This is for our bare-metal Optiplex 3050
try_nvme() {
  echo "Failed to mount, trying NVMe device."
  umount /newroot
  mknod /dev/nvme0n1p3 b 259 3
  mount /dev/nvme0n1p3 /newroot || error
}

try_sdb3() {
  echo "Failed to mount, trying sdb3 device."
  umount /newroot
  mknod /dev/sdb3 b 8 19
  mount /dev/sdb3 /newroot || try_nvme
}


##
### Install disk
### We have a disk B with 2 partitions for now
mknod /dev/sdb  b 8 16
mknod /dev/sdb1 b 8 17
mknod /dev/sdb2 b 8 18
###
#### Create new root
mkdir /newroot
mount /dev/sdb2 /newroot || try_sdb3
ls /newroot/sbin || try_sdb3
###
#### Switch root
exec switch_root /newroot /sbin/init || error

exec /bin/sh
