# qc01-haveALook

The file provided (```challenge.jpg```) contains the following QR Code:


![challenge](/images/challenge.jpg)

Using [Cyberchef](https://gchq.github.io/CyberChef/) **"Parse QR Code"** functionality allows to read it: 

    https://www.youtube.com/watch?v=dQw4w9WgXcQ#PrinceProcessorCanHelpWithTheTitle

This **link** redirects to a very famous meme song (you know which one).

The fragment identifier **(#PrinceProcessorCanHelpWithTheTitle)** is interesting. After searching on the web, i discovered that [princeprocessor](https://github.com/hashcat/princeprocessor) is a password candidate generator.

At this point, following this hint, i defined a simple text file (```wordlist.txt```) with an entry for each letter of the song title:

```
    Never
    Gonna
    Give
    You
    Up
```

and then run the following command to obtain the final password candidates:
```terminal
    princeprocessor wordlist.txt -o princeprocessor_wordlist.txt 
```

Since we are dealing with passwords and an image, i supposed the flag to be contained into the original image, protected by one of the previously generated passwords.

I used [stegseek](https://github.com/RickdeJager/stegseek) to try extract some data:
    
```terminal
    stegseek challenge.jpg --wordlist princeprocessor_wordlist.txt
```
and obtained as output:
```bash
    [i] Found passphrase: "NeverUpYouGive"
    [i] Original filename: "secret-flag.txt".
    [i] Extracting to "challenge.jpg.out".
```

which contained the flag **```PTR{R1ckR0ll&St3ganogr4phyComb0}```**