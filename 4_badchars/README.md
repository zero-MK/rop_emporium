via：https://ropemporium.com/challenge/badchars.html

# badchars

An arbitrary write challenge with a twist; certain input characters get mangled before finding their way onto the stack. Find a way to deal with this and craft your exploit.
Click below to download the binary.

[64bit](https://ropemporium.com/binary/badchars.zip) [32bit](https://ropemporium.com/binary/badchars32.zip)

## The good, the bad

Dealing with bad characters is frequently necessary in exploit development and you've probably had to deal with them before when encoding shellcode. Badchars are the reason that encoders such as shikata-ga-nai exist. Remember whilst constructing your ROP chain that the badchars apply to every character you use, not just parameters but addresses too. *To mitigate the need for much RE the binary will list the badchars when you run it.*

### Options

ropper has a bad characters option to help you avoid using gadgets whose address will terminate your chain prematurely, it will certainly come in handy.

### Moar XOR

You'll still need to deal with writing a string into memory, similar to the write4 challenge, that may have badchars in it. Think about how we're going to overcome this obstacle; could we use gadgets to change the string once it's in memory? Are the mutations the badchars undergo predictable or could we remove them from our string entirely so we know what will end up in memory then change them later?

### Helper functions

It's almost certainly worth your time writing a helper function for this challenge. Perhaps one that takes as parameters a string, it's desired location in memory and an array of badchars. It could then write the string into memory and deal with the badchars afterwards. There's always a chance you could find a string that does what you want and doesn't contain any badchars either...