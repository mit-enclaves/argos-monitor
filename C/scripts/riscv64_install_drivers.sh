#!/bin/bash

#sudo insmod /tyche/tyche-capabilities/tyche-capabilities.ko
#sudo insmod /tyche/tyche-enclave/tyche_enclave.ko
#sudo chmod 777 /dev/tyche_enclave

sudo insmod /tyche/drivers/tyche.ko
sudo chmod 777 /dev/tyche
sudo cp -r /tyche/programs /root

# The commands to use in the ramfs are below: 
#insmod /tyche/drivers/tyche.ko
#mknod /dev/tyche c 244 0
#chmod 777 /dev/tyche
