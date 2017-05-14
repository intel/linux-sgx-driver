# Contributing

## Issues

linux-sgx-driver GitHub Issues tracks SGX out-of-tree kernel mode driver design and development issues, bugs.
Please note Intel is concurrently working on upstreaming an in-tree driver. This driver will be used untill the upstreaming process is completed. 

IMPORTANT: Since current SGX driver's code is a snaphot of the in-kernel SGX module (see README.md), contributions not related to bugs
and not related to kernel version support should go to https://github.com/jsakkine-intel/linux-sgx.git 

When reporting bugs, please provide as much details to reproduce the bug as possible:
* simple user space test code
* kernel version
* system info such as cpu, platform
* stacktrace for crashes or kernel oops if possible

### Contribution Guide

We accept contributions as pull requests on GitHub. More detailed guidelines will be added later. Please follow these simple rules for now: 

* A PR should have a clear purpose, and do one thing only, and nothing more. This will enable us review your PR more quickly.
* Each commit in PR should be a small, atomic change representing one step in development.
* Please squash intermediate steps within PR for bugfixes, style cleanups, reversions, etc., so they would not appear in merged PR history.
* Please explain anything non-obvious from the code in comments, commit messages, or the PR description, as appropriate.

### License

linux-sgx-driver is licensed under the terms in [LICENSE](https://github.com/01org/linux-sgx-driver/blob/master/License.txt). By contributing to the project, you agree to the license and copyright terms therein and release your contribution under these terms.

### Sign your work

Please use the sign-off line at the end of the patch. Your signature certifies that you wrote the patch or otherwise have the right to pass it on as an open-source patch. The rules are pretty simple: if you can certify
the below (from [developercertificate.org](http://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Then you just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@email.com>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

If you set your `user.name` and `user.email` git configs, you can sign your
commit automatically with `git commit -s`.
