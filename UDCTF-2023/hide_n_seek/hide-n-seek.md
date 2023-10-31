# Hide n Seek

This challenge provides two files: `LOLisCapatlized.wav` and `STEG_O_SAURS.jpeg`

the .wav file is a morse code recording, by decoding it i obtained the string:

    GIVEMETHEFLAGLOL

As the file name says, the "lol" is capitalized i.e. i assume the correct string
to be

    givemetheflagLOL

tried to extract with steghide from the image using that passphrase 

    steghide extract -sf STEG_O_SAURS.jpeg -p givemetheflagLOL
    wrote extracted data to "flaglol.txt".

which contained the following string:

    UDCT{01111001 01000000 01010101 01011111 01100011 01000001 01011110 01101110 01011111 01101000 00100001 01100100 00110011 00111111 01011111 01101100 01001111 01101100 01011111 01110011 01010100 00110011 01000111 01101111}

and after decoding from binary finally we got the flag:

    UDCTF{y@U_cA^n_h!d3?_lOl_sT3Go}
