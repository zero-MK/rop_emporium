via：https://ropemporium.com/challenge/callme.html

# callme

Reliably make consecutive calls to imported functions. Use some new techniques and learn about the Procedure Linkage Table.
Click below to download the binary.

[64bit](https://ropemporium.com/binary/callme.zip) [32bit](https://ropemporium.com/binary/callme32.zip)

## Failure is not an option

How do you make consecutive calls to a function from your ROP chain that won't crash afterwards? If you keep using the call instructions already present in the binary your chains will eventually fail, especially when exploiting 32 bit binaries. Consider why this might be the case.

### Procedure Linkage

The Procedure Linkage Table (PLT) is used to resolve function addresses in imported libraries at runtime, it's worth reading up about it. See appendix A in the [beginner's guide](https://ropemporium.com/guide.html) for a brief explanation of how the PLT is used in lazy binding. Even better, go ahead and step through the lazy linking process in a debugger, it's important you understand what resides at the addresses reported to you by commands like rabin2 -i <binary> and rabin2 -R <binary>

### Correct order

Important:
To dispose of the need for any RE we'll tell you the following:
You must call **callme_one(), callme_two()** and **callme_three()** in that order, each with the arguments 1,2,3 e.g. **callme_one(1,2,3)** to print the flag. The solution here is simple enough, use your knowledge about what resides in the PLT to call the callme_ functions in the above order and with the correct arguments. *Don't get distracted by the incorrect calls to these functions made in the binary, they're there to ensure these functions get linked. You can also ignore the .dat files and the encrypted flag in this challenge, they're there to ensure the functions must be called in the correct order.*