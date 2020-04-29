via：https://ropemporium.com/challenge/pivot.html

# pivot

There's only enough space for a three-link chain on the stack but you've been given space to stash a much larger ROP chain elsewhere. Learn how to pivot the stack onto a new location.
Click below to download the binary.

[64bit](https://ropemporium.com/binary/pivot.zip) [32bit](https://ropemporium.com/binary/pivot32.zip)

## But why

To "stack pivot" just means to move the stack pointer elsewhere. It's a useful ROP technique and applies in cases where your initial chain is limited in size (as it is here) or you've been able to write a ROP chain elsewhere in memory (a heap spray perhaps) and need to 'pivot' onto that new chain because you don't control the stack.

### There's more

In this challenge you'll also need to apply what you've previously learned about the .plt and .got.plt sections of ELF binaries. If you haven't already read appendix A in the [beginner's guide](https://ropemporium.com/guide.html), this would be a good time. This challenge imports a function called foothold_function() from a library that also contains a nice ret2win function.

### Offset

The ret2win() function in the libpivot.so shared object isn't imported, but that doesn't mean you can't call it using ROP! You'll need to find the .got.plt entry of foothold_function() and add the offset of ret2win() to it to resolve its actual address. Notice that foothold_function() isn't called during normal program flow, you'll have to call it first to populate the .got.plt entry.