via：https://ropemporium.com/challenge/fluff.html

# fluff

The concept here is identical to the write4 challenge. The only difference is we may struggle to find gadgets that will get the job done. If we take the time to consider a different approach we'll succeed.
Click below to download the binary.

[64bit](https://ropemporium.com/binary/fluff.zip) [32bit](https://ropemporium.com/binary/fluff32.zip)

## Working backwards

Once we've employed our usual drills of checking protections and searching for interesting symbols and strings we can think about what we're trying to acheive and plan our chain. A solid approach is to work backwards; we'll need a mov [reg], reg or something equivalent to make the actual write so we can start there.

### Do it!

There's not much more to this challenge, we just have to think about ways to move data into the registers we want to control. Sometimes we'll need to take an indirect approach, especially in smaller binaries with fewer available gadgets like this one. Once you've got a working write primitive go ahead and craft your solution. If you don't feel like doing the hard work note that the 64 bit version of this challenge can also be pwned using the same single link chain that works on write4 🤦‍♂️