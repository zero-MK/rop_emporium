via：https://ropemporium.com/challenge/write4.html

# write4

Our first foray into proper gadget use. A call to system() is still present but we'll need to write a string into memory somehow.
Click below to download the binary.

[64bit](https://ropemporium.com/binary/write4.zip) [32bit](https://ropemporium.com/binary/write432.zip)

## Cord cut

On completing our usual checks for interesting strings and symbols in this binary we're confronted with the stark truth that our favourite string "/bin/cat flag.txt" is not present this time. Although you'll see later that there are other ways around this problem, such as resolving dynamically loaded libraries and using the strings present in those, we'll stick to the challenge goal which is learning how to get data into the target process's virtual address space via the magic of ROP.

### Read/Write

The important thing to realise is that ROP is just a form of arbitrary code execution and if we're creative we can leverage it to do things like write to or read from memory. The question is what mechanism are we going to use to solve this problem, is there any built-in functionality to do the writing or do we need to use gadgets? In this challenge we won't be using built-in functionality since that's too similar to the previous challenges, instead we'll be looking for gadgets that let us write a value to memory such as mov [reg], reg. Nonetheless it is possible to solve this challenge by leveraging functions like fgets() to write to memory locations of your choosing so it's worth trying to do it that way once you've solved it using the intended technique.

### What/Where

Perhaps the most important thing to consider in this challenge is **where** we're going to write our string. Use rabin2 or readelf to check out the different sections of this binary and their permissions. Learn a little about ELF sections and their purpose. Consider how much space each section might give you to work with and whether corrupting the information stored at these locations will cause you problems later if you need some kind of stability from this binary.

### Decisions, decisions

Once you've figured out how to write your string into memory and where to write it, go ahead and call system() with its location as your only argument. Are you going to cat flag.txt or drop a shell with /bin/sh? Try to wrap some of your functionality in helper functions, if you can write a 4 or 8 byte value to a location in memory, can you craft a function (in python using pwntools for example) that takes a string and a memory location and returns a ROP chain that will write that string to your chosen location? Crafting templates like this will make your life much easier in the long run.

### So much room for activities

There are indeed three very different ways to solve the 64 bit version of this challenge, including the intended method. Built-in functionality will give you a win if you're willing to borrow a technique from the 'pivot' challenge and an oversight in how the pwnme() function was constructed can get you a shell in a single link chain 🤫