via：https://ropemporium.com/challenge/ret2csu.html

# ret2csu

We're back in ret2win territory, but this time without the useful gadgets. How will we populate the rdx register without a pop rdx?
Click below to download the binary.

[64bit](https://ropemporium.com/binary/ret2csu.zip)

## Same same, but different

The challenge is simple: call the **ret2win()** function, the caveat this time is that the third argument (which you know by now is stored in the rdx register on x86_64 Linux) must be 0xdeadcafebabebeef. Populating this elusive register using ROP can prove more difficult than you might first think, especially in smaller binaries with fewer gadgets. This can become particularly irksome since many useful GLIBC functions require three arguments.

### So little room for activities

Start by using ropper to search for sensible gadgets, if there's no pop rdx perhaps there's a mov rdx, rbp that you could chain with a pop rbp. You might consider avoiding the issue entirely by returning to the fgets() code within the pwnme() function but this may prove to be difficult since the .got.plt entries of fgets() and some other functions have been tampered. If you're all out of ideas go ahead and read the last section.

### Universal

Fortunately some very smart people have come up with a solution to your problem and as is customary in infosec given it a collection of pretentious names, including "Universal ROP", "μROP", "return-to-csu" or just "ret2csu". You can learn all you need to on the subject from these [BlackHat Asia slides](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf). Note that more recent versions of gcc may use different registers from the example in __libc_csu_init(), including the version that compiled this challenge.