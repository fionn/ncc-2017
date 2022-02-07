# Challenge 3 - ScreenApp

Can you find anything wrong with my application? I bought it on the MobileStore for a few dollars💰 and it allows me to pair my smartphone with an airplane TV. I can then control different things on the screen and get information about my account directly from my phone. It’s pretty neat! If you’ve ever had to deal with these old tactile screens on a flight before… you know what I’m talking about.

So whenever I find myself in an airplane with that kind of monitor in front of my seat, I can find the pairing page on the menu of that little screen to start the process. It will display 4 random digits that I will have to type into the smartphone app. After that, this 4-digit number is hashed with SHA-256 to produce a key `k`.

I am then asked to connect to the video display’s own wifi hotspot. I know which wifi it is thanks to the SSID displayed on it!

An ephemeral Diffie-Hellman key exchange with a modulus of 768 bits is done between the app and the screen, then both ends use the shared secret created out of that key exchange XOR’ed with the previous key `k` as the session key. This session key is used to encrypt any data from the screen to the phone and from the phone to the screen using AES in ECB mode.

It looks secure, but I’m not too sure since I’m a noob :)

Thanks!

Bob
