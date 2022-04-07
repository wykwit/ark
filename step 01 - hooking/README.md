# hooking

Function hooking is all the fun in rootkit development!


## symbol table

There are a few traditional ways to hook kernel functions.
Rootkits usually target system call handlers.
Each system call has proper handler function assigned in kernel's symbol table or `sys_call_table`.
The very basic way to hook a function is simply to get the original system call handler's address from that table and then replace it with your own.

We could easily do that on kernel version 2.4. The example is given in `attack-2.4` directory.
[This stackoverflow question (link)](https://stackoverflow.com/questions/70053823/syscallsys-getuid-returns-different-result-from-getuid) gives some context on why we overwrite two syscalls (getuid and getuid32) in that module.

Starting from version 2.6 the symbol table is not exported for use by kernel modules anymore and therefore it is a little bit harder to find it and modify the entries.

The first defense idea is to make a copy of the symbol table and check (periodically or per user request) whether the original one matches our copy.
Although incomplete, this approach is fine and it's demonstrated under the `defense-2.4` directory.

Phrack article "Linux on-the-fly kernel patching without LKM" describes how this defense can easily be fooled.
It demonstrates a typical rootkit attack (but this time performed from userspace with the use of `/dev/kmem`) and a way to obtain the sys\_call\_table address.
Instead of overwriting handler addresses in the table, the interrupt handler function is overwritten to use modified sys\_call\_table copy.
A prime example of a rootkit - SucKIT is introduced as an attachment to the article.

For reference: [Volume 0x0b, Issue 0x3a, Phile #0x07 of 0x0e](http://phrack.org/issues/58/7.html)


## patching

Another way to hook a function is to patch in unconditional jumps to some external code (which could also contain that part of the function which was overwritten by our jump instruction) and at the end jump from that code back to the rest of the original function.
We can try to defend from this by hashing function code and periodically checking to make sure it has not been changed.
This defense method should work against SucKIT.
We would pretty much track integrity of the function's code, possibly keeping it's backup somewhere else in memory.
I've tried it with a newer kernel version, you can see my attempt in the `defense-4.4` directory.
In kernel 2.4 the syscall handler was explicilty defined in [/arch/i386/kernel/entry.S](https://elixir.bootlin.com/linux/2.4.31/source/arch/i386/kernel/entry.S#L202), but now it got a little complicated and it's not that easy to watch a single function like this.
However, we can still watch other important functions to prevent them from being overwritten.

With something like detour traversal (following jumps) we could also tell which module contains malicious code, in case the rootkit inserted jump instructions somewhere.
Perhaps we could count all the jumps and their destination addresses to prevent something funny from happening to our running code.
If any of the jump destinations is overwritten or a new one pops up, the count will change and we can investigate suspicious addresses with different count to see where they belong.


## write protection

Reading and writing arbitrary memory is fun in and of itself. Since we're running on kernel level there isn't much that could stop us from doing that - besides hardware or a hypervisor. It just so happens that CPU has a control registers that could for instance deny us the pleasure of arbitrary write access: bit 16 of cr0 is a write protect bit.
As an attacker with kernel-level access we could simply flip those annoying bits on and off when necessary, but it's still an inconvenience worth keeping in mind.


## interrupt descriptor table

IDT in the context of function hooking is similar to symbol tables, but on a lower level.
For each interrupt it keeps an address to a proper handler.
Notably, it contains a syscall dispatcher for interrupt 0x80.
We can both attack and defend it in a similar way we would targeting a symbol table.

IDT can be accessed directly from asm, for instance with the `sidt` intstruction, like in the aforementioned Phrack article.
The same instruction can be disabled for userspace by setting a proper bit of control register cr4.

OSDev Wiki has an article on IDT: [https://wiki.osdev.org/Interrupt\_Descriptor\_Table](https://wiki.osdev.org/Interrupt_Descriptor_Table)


## tracing

There are other legitimate ways of hooking functions, for example with kprobe or ftrace.

Some methods are described in kernel documentation here: [https://www.kernel.org/doc/html/latest/livepatch/livepatch.html](https://www.kernel.org/doc/html/latest/livepatch/livepatch.html)

Tracing is described in more detail here: [https://www.kernel.org/doc/html/latest/trace/index.html](https://www.kernel.org/doc/html/latest/trace/index.html)


