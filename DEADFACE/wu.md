## Intro
This is my writeups for some deadface challenges I've done as a member of [PsychoBash](https://ctftime.org/team/358981), it's mostly crypto and reverse :).

## Reverse Engineering

## Cryptography
### Social Pressure
Just use atbash cipher from [dcode](https://www.dcode.fr/chiffre-atbash), which allows us to decipher the conversation :
```
luciafer 

Hey lilith, big news! We're going after De Monne Financial next. Their security measures have some holes that we're gonna exploit big time! I've been poking around and found some SQL vulnerabilities we can leverage for maximum chaos.

Remember that IT guy I mentioned before? Turns out, he’s a real chatty Cathy on social media. Think we can use some good ol' social engineering to our advantage. We’ll get him spewing passwords like a leaky faucet. Plus, with your OSINT skills and my SQL magic, they won’t see what hit 'em.

lilith

I've already started some OSINT recon and guess what? Found some juicy deets about their IT team on LinkedIn. People overshare so much, it's practically a goldmine. Social engineering that chatty dude should be a breeze; I'll craft a legend that'll have him spilling everything.

luciafer

Yaaas, this is gonna be legendary! Loving the enthusiasm. And Elroy Ongaro? That guy's practically rolling out the red carpet for us with how much he shares online. Can't believe how easy some of these targets make it.

lilith

Absolutely! Elroy Ongaro has no idea what's coming his way. I've already got a few angles in mind to get him talking. Social engineering these types is always a thrill.

I'll start drafting some personas and scripts. Once he's under our influence, we can orchestrate the SQL exploit seamlessly. Your expertise in that area is going to be crucial.

# flag{Elroy_Ongaro}
```
### Discreet Logging 
In this challenge we have access to some kind of logs of computation : 
```
computing discrete log for prime: 191
discrete log found: 25
computing discrete log for prime: 1621
discrete log found: 293
computing discrete log for prime: 61
discrete log found: 49
computing discrete log for prime: 2447
discrete log found: 2105
...
```
At first I thought it was logging about DLP (Discrete Logarithm Problem) where we have to solve equation $`g^x = h \ (mod \ p)`$ knowing $`(x, p)`$ and I thought flag char was the $`h`$ value, but actually it was just CRT (Chinese Remainder Theorem) which allow us to solve congruence system see details [here](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).
So first I've written this script to parse data from the web page logs : 
```python
import requests

url = "https://cyberhacktics.sfo2.digitaloceanspaces.com/DEADFACECTF2024/challenges/crypto/crypto13/ecdh_crack_20241013.log"
PRIMES = []
LOGS = []
resp = requests.get(url)
data = resp.text

for line in data.split('\n'):
    if 'computing' in line:
        PRIMES.append(int(line.replace('computing discrete log for prime: ', '')))
    else:
        LOGS.append(int(line.replace('discrete log found: ', '')))
print(PRIMES)
print(LOGS)
```
Finally in sage we can do this : 
```python
from Crypto.Util.number import long_to_bytes
nis = [191, 1621, 61, 2447, 991, 1297, 47, 1049, 347, 283, 2617, 1429, 167, 307, 431, 683, 1627, 17, 827, 97, 523, 151, 37, 2269, 1733, 3, 19, 439]
cis = [25, 293, 49, 2105, 564, 50, 13, 21, 229, 257, 307, 511, 124, 7, 63, 476, 1054, 2, 793, 60, 270, 145, 32, 796, 1041, 1, 9, 60]
print(long_to_bytes(crt(cis, nis)) # flag{ch1n3s3-r3mAind3r-D-l0g}
```

### Drink Up
Challenge provide this image : <br>
<img src="callingcard.png" /><br>
We also have the ciphertext written on the image : `zxk1ehfZ/kx7tzSyQeSm2XuGitnxsN8rG/mwxNaCjFFc2rCrTTWpwViZFpwI4xRccvdwm/Ta6l3GFeaPs96l7BPziIu+DsfoS6bdy5ByHSyW+D5bCgtTCuoVvMOlPC7xILtjlt6/Ky6ZPaV40gfmtM/iuRGR+zveFLNyWy9Tlu3TnOaq0lP6wp65lGEFBTHPSwho0jIP47pxoKryxnh7svJrTD1wh+D+YudNjDpPr39yH/iMlU+5xiK2dXjiD0UtL3vSSQ55MLCPpN/kFW6AuO2OEuadKXg2XYiXnAkLJcUxGdZhP7+Lo4LG3m5HsHdBmul5pX9gcvERFQSZOy2QfEv3+vRfLfoJPq6WQnBjwXUoVo/YHeD8SS+TDvg=`<br>
The word "XXTEA" written on the image refers to the cipher that has been used, also I've tried different posssibilities of key like "only2ingredients..."<br>
And I've finally found the key just by using words in the image, here is the solution script to decipher xxtea using python : <br>
```python
# pip install xxtea-py
import base64
cipher_text_base64 = "zxk1ehfZ/kx7tzSyQeSm2XuGitnxsN8rG/mwxNaCjFFc2rCrTTWpwViZFpwI4xRccvdwm/Ta6l3GFeaPs96l7BPziIu+DsfoS6bdy5ByHSyW+D5bCgtTCuoVvMOlPC7xILtjlt6/Ky6ZPaV40gfmtM/iuRGR+zveFLNyWy9Tlu3TnOaq0lP6wp65lGEFBTHPSwho0jIP47pxoKryxnh7svJrTD1wh+D+YudNjDpPr39yH/iMlU+5xiK2dXjiD0UtL3vSSQ55MLCPpN/kFW6AuO2OEuadKXg2XYiXnAkLJcUxGdZhP7+Lo4LG3m5HsHdBmul5pX9gcvERFQSZOy2QfEv3+vRfLfoJPq6WQnBjwXUoVo/YHeD8SS+TDvg="
cipher_text = base64.b64decode(cipher_text_base64)

key = b"Tea Turned Up to the Max"
plain_text = xxtea.decrypt(cipher_text, key)
b"Ah, I see you've stumbled upon my little souvenir. By now, you must be feeling pretty exposed. It's a shame companies like yours invest in everything but proper security. Remember, this isn't personal; it's just your turn. Sleep tight, spookyboi was here. flag{br3wed_4_the_B0ld!}"
```
