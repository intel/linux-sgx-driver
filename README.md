Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx-driver

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software. The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. 

Starting from 05/2017, we are importing the sgx driver code from the in-kernel sgx linux repository from git hub repository:
https://github.com/jsakkine-intel/linux-sgx.git. This repository includes sgx ring 0 support within the linux kernel.
The motivation of this decision is to maintain one source for the SGX kernel module either external or in kernel.
Directory inker2ext includes a script file and a patch file used to migrate the in-kernel code to this repository.

License
-------
See License.txt for details.

Contributing
-------
See CONTRIBUTING.md for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](http://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)

Build and Install the Intel(R) SGX Driver
-----------------------------------------

### Prerequisites
- Ensure that you have the following required operating systems:  
  * Ubuntu* Desktop-16.04-LTS 64bits
  * Red Hat Enterprise Linux Server release 7.2 64bits
  * CentOS 7.3.1611 64bits
- Ensure that you have the following required hardware:  
  * 6th Generation Intel(R) Core(TM) Processor (code named Skylake)
  * 7th Generation Intel(R) Core(TM) Processor (code named Kaby Lake)
- Configure the system with the **SGX hardware enabled** option.

### Build the Intel(R) SGX Driver
To build Intel(R) SGX driver, change the directory to the driver path and enter the following command:
```
$ make
```
You can find the driver *isgx.ko* generated in the same directory.

### Install the Intel(R) SGX Driver
To install the Intel(R) SGX driver, enter the following command with root privilege:
```
$ sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
$ sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
$ sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
$ sudo /sbin/depmod
$ sudo /sbin/modprobe isgx
```
On Red Hat Enterprise Linux Server or CentOS, need to run below command on each reboot
```
$ sudo /sbin/modprobe isgx
```    

### Uninstall the Intel(R) SGX Driver
Before uninstall the Intel(R) SGX driver, make sure the aesmd service is stopped. See the topic, Start or Stop aesmd Service, on how to stop the aesmd service.  
To uninstall the Intel(R) SGX driver, enter the following commands: 
```
$ sudo /sbin/modprobe -r isgx
$ sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
$ sudo /sbin/depmod
$ sudo /bin/sed -i '/^isgx$/d' /etc/modules
```
