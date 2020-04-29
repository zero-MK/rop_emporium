via：https://ropemporium.com/challenge/split.html

# split

In this challenge the elements that allowed you to complete the ret2win challenge are still present, they've just been split apart. Find them and recombine them using a short ROP chain.
Click below to download the binary.

[64bit](https://ropemporium.com/binary/split.zip) [32bit](https://ropemporium.com/binary/split32.zip)

## Still here

I'll let you in on a secret; that useful string "/bin/cat flag.txt" is still present in this binary, as is a call to system(). It's just a case of finding them and chaining them together to make the magic happen.

### I'm not lying

Before we begin let's check the permissions on our target binary. We're employing ROP due to the presence of NX, but we'd feel pretty stupid if it turned out that none of these binaries were compiled with NX enabled. We'll check that this isn't the case and we can't just JMP ESP with a little shellcode. rabin2 -I split lets us know that NX is indeed enabled:

![NX enabled](split_protections.png)



### Treasure hunting

Don't just take my word for it, let's check the call to system() and that useful string are actually here. Afterall if I hadn't mentioned that they were still there how would you know where to start? Go ahead and use rabin2 or any of the tools mentioned in the [beginner's guide](https://ropemporium.com/guide.html) to locate useful strings and note their location. Now ensure that system() is imported, rabin2 or readelf are here to help.

### All together now

Now that you've gathered the elements of your exploit you can start to piece them together, you want to call system() with the "/bin/cat flag.txt" string as the only argument. You'll also have to start dealing with the differences between 32 & 64bit calling conventions.

### Finish the job

Once you've planned your chain, craft a suitable solution. We're still trying to read the contents of the flag.txt file on the imaginary remote machine. You can do the 32bit challenge with just a 2 link chain and the 64bit challenge with a 3 link chain.