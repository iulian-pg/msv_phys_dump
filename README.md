# msv_phys_dump

**Using the `eneio64.sys` Vulnerable Driver to Extract NTLM Hashes from LSASS (via Physical Memory Only)**

- This exploit targets [`eneio64.sys`](https://www.loldrivers.io/drivers/90ecbbf7-b02f-424d-8b7d-56cc9e3b5873/), a well-known vulnerable driver that provides read/write primitives for the system’s physical memory.
- This exploit was tested only on Windows 10 builds 14393, 19041, and 19045. For other versions, the hardcoded `EPROCESS` and `lsass` offsets need to be adjusted.
- This project was inspired by [Xacone](https://github.com/Xacone/Eneio64-Driver-Exploit) and [Adepts-of-0xCC](https://github.com/Adepts-Of-0xCC/SnoopyOwl).
- To locate the PML4 base, the exploit searches for the system `EPROCESS` and then parses the `DirectoryTableBase`. While not the most optimal solution, it is reliable and surprisingly fast taking about ~8 seconds on a system with 16 GB of RAM.

The main benefit of this approach is that it avoids opening or reusing handles for LSASS, making it easier to evade detection. Additionally, the exploit itself does not require administrative privileges. If a vulnerable driver is already installed, it can be executed with medium integrity. However, if employing the BYOVD approach (which will be the case most of the time), administrative privileges will obviously be required to install the driver.

The main downside is the need for a vulnerable driver that goes undetected. eneio64.sys, for instance, is quite old and is flagged by most EDR solutions. However, since this project is intended purely as a proof of concept, there was no need to search for an undetected alternative.

Since the exploit only reads memory and does not perform any writes or modifications, the risk of a BSOD should be low. I have not experienced any crashes during testing, but you never know 🤷‍♂️.

Execution:

![imagen](https://github.com/user-attachments/assets/83ad0106-42cf-4a9b-9b0e-078eb8b29640)
