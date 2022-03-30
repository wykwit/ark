# testing

In the zeroth step we shall document our testing setup.


## distro

Slackware will be our testing Linux distribution.

On Wikipedia there is a list of releases along with associated kernel versions ([link](https://en.wikipedia.org/wiki/Slackware#Releases)).
We will use what is appropriate for each step.

You can download any Slackware release from a mirror: [https://mirrors.slackware.com/slackware/](https://mirrors.slackware.com/slackware/)

Conveniently small install images are available here: [http://www.slackware.com/~alien/slackboot/mini/](http://www.slackware.com/~alien/slackboot/mini/)

The latest release with a 2.4 kernel is Slackware 11. We can easily set it up with qemu.

Slackware 14.2 comes with a 4.4 kernel which is our final target.


## qemu

To create an empty disk image:
```
$ qemu-img create -f qcow2 slackware-11.qcow2 4G
```

Then we run with the CD:
```
$ qemu-system-x86_64 -enable-kvm -m 1G -hda slackware-11.qcow2 -hdb slackware-11.img -cdrom slackware-11.0-mini-install.iso
```
and proceed with the installation.


Once installed we can boot with simply:
```
$ qemu-system-x86_64 -enable-kvm -m 1G -hda slackware-11.qcow2
```

We can also pass and mount a directory (as a FAT filesystem) and boot with:
```
$ qemu-system-x86_64 -enable-kvm -m 1G -hda slackware-11.qcow2 -drive format=raw,file=fat:rw:/path/to/workdir
```
It will show up as `/dev/hdb1` and can be mounted from within the guest system.
Changes to that drive should be discarded.


## compilation

Modules can be compiled within the guest system.

As a sanity check the `attack` subdirectories for this step contain simple hello-world kernel modules.
Between kernel versions 2.4 and 2.6 the structure of a module and the build process changed a lot.

2.4:
```
$ gcc -c hello-world.c    # compile
$ insmod hello-world.o    # load
$ rmmod hello-world       # unload
```

2.6 and newer:
```
$ make -C /lib/modules/$(uname -r)/build M=$PWD modules
$ insmod hello-world.ko
$ rmmod hello-world
```

Display logs to see the results:
```
$ dmesg
```


## linting

We have to ensure our code is of decent quality and readable enough. For that purpose we shall use the clang-tidy linter.

Kernel coding style is described here: [https://www.kernel.org/doc/html/latest/process/coding-style.html](https://www.kernel.org/doc/html/latest/process/coding-style.html)

The linter is documented here: [https://clang.llvm.org/extra/clang-tidy/](https://clang.llvm.org/extra/clang-tidy/)


