# ark

Anti-rootkit Linux Kernel Module


## introduction

The goal of the project is to explore kernel security by implementing an anti-rootkit solution.
We will look at key kernel components (security-wise) and see how rootkits could abuse them.
Defense mechanisms such as AppArmor and SELinux are out of scope for this project.

Target for the final solution is kernel version >=4.0.
However, to demonstrate the basics first, we start off with older kernel versions and see how they've evolved.
Version 2.4 and 2.6 are described pretty well in the literature mentioned below.
They lack security features present in newer versions which makes our demonstations much easier.

If you're not sure what a rootkit is, go check Wikipedia.


## literature

Interesting papers:
 - A. Baliga, V. Ganapathy and L. Iftode. "Detecting Kernel-Level Rootkits Using Data Structure Invariants." IEEE Transactions on Dependable and Secure Computing 8.5 (2011): 670-84. doi: [10.1109/TDSC.2010.38.](https://doi.org/10.1109/TDSC.2010.38)
 - Teh Jia Yew, Khairulmizam Samsudin, Nur Izura Udzir, and Shaiful Jahari Hashim. "Rootkit Guard (RG) - An Architecture for Rootkit Resistant File-system Implementation Based on TPM." Pertanika Journal of Science & Technology 21.2 (2013): 507-20. [Web.](https://myjurnal.mohe.gov.my/filebank/published_article/28630/18.pdf)

Books:
 - "Linux Kernel Internals" by: M. Beck, H. Böhme, M. Dziadzka, U. Kunitz, R. Magnus, D. Verworner
 - "Understanding the Linux Kernel" by: Daniel P. Bovet, Marco Cesati
 - "Linux Device Drivers" by: Jonathan Corbet, Alessandro Rubini, Greg Kroah-Hartman

And too many internet resources to list them all.
Official kernel documentation included.

Another repository explaining kernel hacking (and rootkits):
 - [https://github.com/xcellerator/linux\_kernel\_hacking](https://github.com/xcellerator/linux_kernel_hacking)

Another anti-rootkit project:
 - [https://github.com/nbulischeck/tyton](https://github.com/nbulischeck/tyton)

Other online resources:
 - [kernel source code browser](https://elixir.bootlin.com/linux/latest/source)
 - [lectures and labs on the Linux kernel](https://linux-kernel-labs.github.io/refs/heads/master/index.html)
 - [The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/)
 - [TLDP website](https://tldp.org/)
 - [LWN website](https://lwn.net/)
 - [Automotive Grade Linux documentation](https://agl-docs.readthedocs.io/en/master/#2_Architecture_Guides/2_Security_Blueprint/4_Kernel/)


## repository structure

We dig into the kernel in steps, each named after the concept explored in that part.
Steps consist of demonstrative "attack" and "defense" kernel modules.
The obvious assumption is that when we defend, we need the "defense" module to be loaded before the "attack" one.
Further explanations for each step should be given in proper README files.


## license

GPLv3 unless stated otherwise.


