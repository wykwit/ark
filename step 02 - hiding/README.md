# hiding

Rootkits will try to conceal their presence and hide whetever evil stuff they've dropped on the system.
Hiding things is how they are useful.
For variety we will have a look at a few examples.

Our first example is the Diamorphine rootkit.
It allows for hiding processes and privilege escalation with a custom signal.
With a different custom signal it can also turn the module invisible (hide or unhide itself).

Diamorphine rootkit: [https://github.com/m0nad/Diamorphine](https://github.com/m0nad/Diamorphine)

Ivyl's rootkit achieves very similar results, but with a completely different method - no sys\_call\_table involved.
It can also hide files and boost privileges to root.

Ivyl's rootkit: [https://github.com/ivyl/rootkit](https://github.com/ivyl/rootkit)

Another fine example is the Suterusu rootkit, which can hide even more things, like: ports, files, directories.
It implements a few ways to obtain the sys\_call\_table, including the SucKIT technique.
Instead of using conventional symbol table overwrites it uses patching in quite an elegant way.

Suterusu rootkit: [https://github.com/mncoppola/suterusu](https://github.com/mncoppola/suterusu)


## files

> In UNIX everything is a file.

It may sound cryptic, but the idea is that every component uses a common interface for interactions.
This interface can be simplified to the idea of a file.
Of course, it's not _every_ system component, but the principle will hold for a lot of stuff exposed to the userspace.
Read on to see how exactly that applies.


## processes

Many userspace tools rely on the content of `/proc` to list running processes.

Some rootkits will therefore hook `getdents` syscall to skip the listing of directories that would reveal PID of a given process.
This allows the rootkit to hide that process and its children from userspace tools such as `ps`.
Diamorphine utilizes that technique.
We've already addressed syscall hooking in the previous step, though.

Another approach is to overwrite functions of a procfs entry such as: `read`, `read_iter`, `iterate`, `readdir`.
This is what Suterusu and Ivyl's rootkit do.
How can we defend against this technique?

The idea is to use the data integrity check that we've used in the previous step to secure syscall functions,
but this time on structs that hold pointers to filesystem handler functions for certain operations.
Each file has a field that points to an instance of this struct and that's how the system knows exactly what to execute when dealing with it.
In filesystem implementations we will see two important struct types in use: `file_operations` and `inode_operations`.
They hold pointers to proper handler functions, but unlike with symbol table, we can't just iterate over the members (I think).
Nonetheless, we can ensure that certain important instances of these don't get overwritten.
In `defense-4.4` module we register a few symbols for procfs and a few for ext4 - the most common filesystem, likely used on the root partition.


## network activity

There are more struct types for managing different operations.
We may stumble upon `seq_operations` in network code.
Suterusu hooks a few functions related to entries under `/proc/net` to hide itself.
Normally they would be accessed similarly to file operations, through reference to the associated struct field.

These functions have been listed as scan targets in the defense module.
Again, as a scan target we want to list both the struct instance and the actual function implementation too.

Listing out every single scan target may turn out to be futile.
The attacker could simply hook somewhere else on the data flow path.
Ultimately, using network straight from the kernel could also be invisible from userspace.
The proper way to address this issue is to monitor the network traffic outside of the user's system.
Network administrators already do this, but it's a topic divergent from ours.


## modules

Loaded modules are stored in a list, so rootkits simply peel themselves off that module list.
There are still other objects associated with a module.
That's probably why Ivyl and Suterusu also remove the module from a (sysfs?) kobject list.
Modules are also held in mod tree for the purpose of faster lookups.
That's why once we have a symbol address from that module the kallsyms lookup will still tell us what the owner module is.

There are a few approaches we can take to counteract module hiding.
These modules must have some memory allocated, so we should be able to spot them somehow.
Perhaps they have some symbols we can access and check.
Maybe we can monitor all the module loads and unloads to see when some module that has previously been loaded suddenly disappears.
Maybe we could compare the 3 stuctures mentioned above to see if a hidden module forgot to remove itself from one of them.

When we find a hidden module the first reflex would probably be to unload it,
but `rmmod` won't work unless we unhide that module first.
Rootkit could also bump up its own reference count to prevent unloading.
Actually, this isn't really an issue for us.
We don't have to unload the module, we only need to neutralize it.
In fact it might even be better to keep the rootkit loaded, so that we can perform some forensic analysis on the system.
Instead of unloading the module we can iterate over its symbols and skim over its data.
We could overwrite some of it, for example write 0xC3 (return in asm) as the first byte of each symbol to ensure there won't be any malicious functions executed anymore.
On the other hand this could mess up forensic analysis a little bit or cause system instability.
If we're not sure how to recover then it might be better to leave everything the way it is.
For that reason in `defense-4.4` module I chose to only report addresses of the offending module's symbols.


