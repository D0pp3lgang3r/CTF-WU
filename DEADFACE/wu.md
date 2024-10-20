## Reverse Engineering

## Cryptography
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
