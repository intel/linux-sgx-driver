Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx-driver

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software. The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. 

Within the linux-sgx-driver project, two versions of the out-of-tree driver are provided. Both versions are compatible with the linux-sgx PSW and SDK:
- SGX 2.0 Linux Driver (sgx2 branch)
  * The sgx2 branch of the linux-sgx-driver project contains the SGX 2.0 Linux Driver. This driver has additional support for SGX 2.0-based features available in upcoming CPUs. This driver has the same behavior as the SGX 1.5 Linux Driver (master) on CPUs without SGX 2.0 support.
- SGX 1.5 Linux Driver (master branch)
  * The master branch of the linux-sgx-driver project tracks the proposed upstream version of the SGX 1.5 driver and does not yet support SGX 2.0-based features.

IMPORTANT:
---------
Starting from 5/10/2019, the master branch (which supports only SGX 1.5-based features) is deprecated and is not supported anymore. Please use the sgx2 branch; it is a super set of the master branch.

License
-------
See License.txt for details.

Contributing
-------
Starting from 05/2017, we are importing the sgx driver code from the in-kernel sgx repository located at git-hub: https://github.com/jsakkine-intel/linux-sgx.git. Any contribution should be done there. Future versions of the sgx driver code will be imported later on. The motivation behind this decision is to maintain a single source code of the sgx linux driver.
An additional directory inker2ext/ has been created, it contains a script and a patch file that can be used in order to separately generate the code base of the sgx external module; it can be used in case someone wants the newest sgx driver as an external module and does not want to wait for next update.

The sgx2 branch hosts an initial implementation supporting SGX 2.0. This patch is maintained in inker2ext/sgx2.patch in the 2.0 branch and will be periodically rebased to take updates from the linux-sgx-driver:master branch. Contributions for this patch should be managed directly through the linux-sgx-driver project on Github.

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
**Note:** To use the SGX 2.0 driver, checkout or download the sgx2 branch and then follow the build instructions.

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

#### Install the SGX Driver on a UEFI Secure Boot Enableed machine

If your machine has UEFI Secure Boot enabled, you may have to follow the following steps to install.
   * Generate the key by using openssl

      For Ubuntu / Debian & Red Hat Enterprise Linux / CentOS:

      ```
      $ openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=isgx Signing/"
      ```

      For SUSE, refer to SUSE official Signing procedure at: [Booting a custom kernel](https://en.opensuse.org/openSUSE:UEFI#Booting_a_custom_kernel)

   * Signing the isgx (Follow the distrubution matches yours):
   
      * For signing the isgx.ko on Ubuntu / Debian, please enter following command with root privilege:
  
      ```
      $ sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der $(modinfo -n isgx)
      ```

      * To sign the isgx.ko on Red Hat Enterprise Linux Server or CentOS, need to run below command with root privileges.

      ```
      $ yum install openssl perl mokutil
      $ perl /usr/src/kernels/$(uname -r)/scripts/sign-file sha256 MOK.priv MOK.der isgx.ko
      ```

  * Check if isgx signed
  ```
  $tail $(modinfo -n isgx) | grep "Module signature appended"
  ```

  * Register the keys to Secure Boot
  ```
  $ sudo mokutil --import MOK.der
  ```

  * Reboot and follow the bluescreen to enrol the MOK, it's operated by shimx64.efi and will happens after POSTS but before system boots.[Image References](https://sourceware.org/systemtap/wiki/SecureBoot)

   * Check if MOK key is registered.
      
      * For Ubuntu / Debian:
      ```
      $ sudo mokutil --test-key MOK.der
      ```

      * For Red Hat Entereprise Linux / CentOS:
      ```
      $ sudo keyctl list %:.system_keyring
      ```

  * Then resume steps from section 'Install the Intel(R) SGX Driver'.

### Uninstall the Intel(R) SGX Driver
Before uninstall the Intel(R) SGX driver, make sure the aesmd service is stopped. See the topic, Start or Stop aesmd Service, on how to stop the aesmd service.  
To uninstall the Intel(R) SGX driver, enter the following commands: 
```
$ sudo /sbin/modprobe -r isgx
$ sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
$ sudo /sbin/depmod
$ sudo /bin/sed -i '/^isgx$/d' /etc/modules
```
