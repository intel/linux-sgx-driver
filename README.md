Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx-driver

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux SGX software stack is comprised of the SGX driver, the SGX SDK, and the SGX Platform Software. The SGX SDK and SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux SGX software stack, which will be used until the driver upstreaming process is complete. 

License
-------
See License.txt for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS][1] project home page on [01.org](http://01.org)
- [Intel(R) SGX Programming Reference][2]
[1]: https://01.org/intel-softwareguard-extensions
[2]: https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf

Build and Install the Intel(R) SGX Driver
-----------------------------------------

###Prerequisites
- Ensure that you have the following required operating systems:  
  Ubuntu\*-14.04-LTS 64bits
- Ensure that you have the following required hardware:  
  6th Generation Intel(R) Core(TM) Processor (code named Skylake)
- Configure the system with the **SGX hardware enabled** option.

###Build the Intel(R) SGX Driver
To build Intel SGX driver, change the directory to the driver path and enter the following command:
```
$ make
```
You can find the driver *isgx.ko* generated in the same directory.

###Install the Intel(R) SGX Driver
To install the Intel SGX driver, enter the following commands: 
```
$ sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
$ sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
$ sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
$ sudo /sbin/depmod
$ sudo /sbin/modprobe isgx
```

###Uninstall the Intel(R) SGX Driver
Before uninstall the Intel SGX driver, make sure the aesmd service is stopped. See the topic, Start or Stop aesmd Service, on how to stop the aesmd service.  
To uninstall the Intel SGX driver, enter the following commands: 
```
$ sudo /sbin/modprobe -r isgx
$ sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
$ sudo /sbin/depmod
$ sudo /bin/sed -i '/^isgx$/d' /etc/modules
```
