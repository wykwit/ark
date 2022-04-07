# triggering

We already trigger on user request when something is written to `/proc/ark`.
Let's explore some other ways of triggering the scan.


## taint

Kernel taint is interesting.
You might've noticed from the previous step that when we `insmod` some custom module we introduce taint to the kernel.

This concept is described here: [https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html](https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html)

There are many useful taint flags which tell us that there might be something wrong with our kernel.
To avoid loading any bad foreign modules we can choose to panic on taint by setting a kernel parameter `panic_on_taint=<bitmask>` on boot.

We are an anti-rootkit though, wouldn't it be nice to scan a module the moment it introduces taint to our kernel?
Malicious module can easily overwrite its own taint flags.
In the previous step during a module scan we listed modules that taint the kernel.
Now we know this approach won't always be effective, so we would like to catch the exact moment when a module is marked with taint.


## kprobes

Basically, we want to execute on particular events.
Whenever `add_taint` is executed we would like to perform our regular scan.
To do this we can use one of the legitimate ways of function tracing that I've mentioned before.
KProbes seem to be the tool for the job.
The issue with this is that we would execute before the function is applied,
so the module is not yet tainted when we perform our scan.
Still, we gain some insight - we know that something caused the function to execute.
We just don't exactly know what.

[An introduction to KProbes (link)](https://lwn.net/Articles/132196/) describes this topic nicely.

Under the hood KProbes use `kallsyms_lookup_name` which we know very well from previous steps.
Starting from kernel version 5.7 that function is not exported anymore.
We can (ab)use KProbes to retrieve its address and restore the previous functionality in our `defense-5.15` module.
Unfortunately, the default kernel on Slackware 15 doesn't have KProbes support compiled in,
so for testing we may want to try Alpine Linux 3.15 instead, which also comes with a 5.15 LTS kernel.


## periodic execution

Periodic execution is one of the project requirements.
The period has to be adjustable by the user.
We can solve it by creating another dedicated procfs entry for adjusting the period
and then scheduling a scan routine for execution.
Delayed execution can be done in a few different ways,
but for our purpose utilizing workqueue seems to be the way to go.
The delay, or our period, is the number of seconds written to `/proc/ark_period`.
Writing "0" to that file will disable periodic scans.


## signing

Of course we like our kernel secure and clean.
To properly prepare and secure our modules we would probably like to sign them.
Rootkits could try to inject themselves into existing modules.
With enforced signatures that should not be possible.
Even if an existing module gets overwritten it will not be loaded.
It's a great way to make sure we prevent any weird stuff from ever getting loaded at all.
Malicious code won't trigger if it can't even be loaded.

ArchWiki better covers this topic: [https://wiki.archlinux.org/title/Signed\_kernel\_modules?useskinversion=1](https://wiki.archlinux.org/title/Signed_kernel_modules?useskinversion=1)


