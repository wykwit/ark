# restructuring

We hit a milestone for the project - a perfect opportunity to restructure our module.
It's time to stop and look back at what we've done so far.

- We've looked at a few different kernel versions: 2.4, 2.6, 4.4, 5.15.
- We've analyzed a few techniques used by rootkits, we've seen how they can modify kernel's functionality and how they can hide.
- We've learned about a few important components of the kernel and some of the mechanisms in use.

There are still some things we've overlooked.
This section is for various improvements of our anti-rootkit solution.


## portability

Up until now in each step we've been targeting a very particular kernel version.
It's time to make the module more portable between kernel versions.
Utilizing `LINUX_VERSION_CODE` and `KERNEL_VERSION` macro we can introduce conditional compilation.
This is the main difference in `defense` module for this step.

I've considered splitting the module into multiple files.
It would be logical to separate it into three or four parts: scanning (+targets), procfs handling, module core.
However, the module is merely a few hundred lines of code.
Considering that all these three parts have to be tightly coupled anyway,
it also makes sense to just leave it the way it is.

To check how portable the module is - we should test it on a few kernel versions.
To go out of our comfort zone we should also test the module on some other distro besides Slackware.
Alpine Linux 3.2 seems like a good candidate. Despite the name it's based on a 3.18 LTS kernel, the last LTS from that series.
I suggest release [alpine-vanilla-3.2.3-x86\_64](https://ftp.icm.edu.pl/pub/Linux/dist/alpine/v3.2/releases/x86_64/alpine-vanilla-3.2.3-x86_64.iso) with vanilla kernel.
For me the module compiled fine.


## scan targets

Scan targets can be refined.
The list can always be adjusted to better fit user's needs.
Possibly the entries could also be better sorted. (...and perhaps slightly better described in a documentation of some sorts? Hey, you can't have it all!)

Scan targets are stored on a very simple one-way list.
The implementation could be improved (a lot), but for now I don't think that's necessary, since the solution is fast enough.

I've realized I was wrong previously and we actually can scan a struct as if it was a table of pointers.
It must be aligned well, preferably not holding any complex structures - just function pointers.
Structs with "ops" and "operations" suffix usually fit that description.
That means we could scan these target struct instances similarly to how we scanned a sys\_call\_table before.
We may also register the sys\_call\_table as a regular scan target with this new mechanism and have almost all the targets listed in one place.
In the end I haven't (yet?) rebuilt the scanning mechanism, but I think this is an interesting idea to explore.


## going further

We could achieve much better security with a hardened kernel.
Looking up "kernel hardening" should give plenty results.

We went all the way around and come back to the topic of debugging.
If we'd like to go further we could take a closer look into ftrace.


