Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx-driver

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software. The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. 

IMPORTANT:
---------
This driver supports SGX 2.0 features, and works with latest Intel(R) SGX PSW on CPUs without Flexible Launch Control (FLC). 
As upstreaming patches for kernel currently does not support SGX 2.0 features, and will not support non-FLC CPUs, this driver is diverged and will remain diverged from the proposed upstreaming version.

The [DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver)
will track more closely with upstream in-kernel support.

License
-------
See License.txt for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](http://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/en-us/articles/intel-sdm)

Build and Install the Intel(R) SGX Driver
-----------------------------------------

### Prerequisites
- Ensure that you have the following required operating systems:  
  * Ubuntu* 16.04.3 LTS Desktop 64bits
  * Ubuntu* 16.04.3 LTS Server 64bits
  * Ubuntu* 18.04 LTS Desktop 64bits
  * Ubuntu* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * Red Hat Enterprise Linux Server release 8.0 64bits
  * CentOS 7.4.1708 64bits
  * SUSE Linux Enterprise Server 12 64bits
- Ensure that you have the following required hardware:  
  * 6th Generation Intel(R) Core(TM) Processor or newer
- Configure the system with the **SGX hardware enabled** option.
- To build the driver, the version of installed kernel headers must match the active kernel version on the system.
  * On Ubuntu
     * To check if matching kernel headers are installed:
        ```
        $ dpkg-query -s linux-headers-$(uname -r)
        ```
     * To install matching headers:
        ```
        $ sudo apt-get install linux-headers-$(uname -r)
        ```
  * On CentOS and RHEL
     * To check if matching kernel headers are installed:
        ```
        $ ls /usr/src/kernels/$(uname -r)
        ``` 
     * To install matching headers:
        ```
        $ sudo yum install kernel-devel
        ```
     * After the above command, if the matching headers are still missing in /usr/src/kernels, try update kernel and reboot usig commands below. Then choose updated kernel on boot menu.
        ```
        $ sudo yum install kernel
        $ sudo reboot
        ```
     * On RHEL 8.0 elfutils-libelf-devel package is required:
        ```
        $ sudo yum install elfutils-libelf-devel
        ```


**Note:** Refer to the *"Intel® SGX Resource Enumeration Leaves"* section in the [Intel SGX Programming reference guide](https://software.intel.com/en-us/articles/intel-sdm) to make sure your cpu has the SGX feature.


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
On SUSE, need to add '--allow-unsupported' flag when executing 'modprobe' command during the SGX driver intallation and on each reboot
```
$ sudo /sbin/modprobe isgx --allow-unsupported
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
