---
layout: post
title:  "Write UP - TPCTF  : No Key [CRYPTO]"
date:   2017-12-05 18:21:27 +0200
categories: CTF-WriteUp
---

![tpctf]({{ site.url }}/assets/tpctf/tpctf_logo.png)



This write Up present the resolution of the <b>Public key? What about <i>no</i> key?</b> Crypto Challenge proposed during the <b>Takoma Park CTF</b> this Week end.

This challenge has been solved 17 times and was rewarded of 60 points.

<br/>


<h2> <b>Introduction</b></h2>

This Challenge was presented this way :

<br/>

![tpctf]({{ site.url }}/assets/tpctf/pres_chall.png)

<br/>

One txt file and one hint is given :

the no_key.txt contains :
![tpctf]({{ site.url }}/assets/tpctf/Cipher.png)

<br/>

and the hint is :

![tpctf]({{ site.url }}/assets/tpctf/hint.png)


Well, now that we have all the elements, we can begin to explain the reasoning to have in order to get the flag.

<br/>
<br/>

<h2> <b> I - Decryption</b></h2>

<h3><b>a - Reminder </b></h3>

First, let's understand what does this <i>txt</i> file mean.
We have a <b>c</b> and a corresponding value as a large integer. In Crypto category, we can easily understand that the <b>c</b> means <b>C</b>ipher and then, the given value is its RSA cipher.
We do not have any other information about this cipher, not even the public key !
<br/><br/>
Before begining to crack it, I would like to remind you how RSA works : (I gonna translate it soon ;) )
<br/><br/>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;![unlucky]({{ site.url }}/assets/RSA.png)
<br/>
The cipher is given by the exponentiation of a <b>primary number e</b> (modulus N), then if you followed your mathematics courses on secondary school you can understand that :
<br/>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;![tpctf]({{ site.url }}/assets/tpctf/sqrt.png)
<br/>
<b>Note :</b> In real life, it doesn't work ;) (I will explain it)
<br/><br/><br/>
<h3><b>b - Crack it ! </b></h3>
In order to crack our <b>C</b>, we gonna try to find if  a prime root exist.
For that, I scripted it :
{% highlight python %}http://localhost:4000/assets/resultat.png
from Arithmetic import *

#Tab of the 1000 smaller primes
prime_tab = [2,3,5,7,11,13,17,19,23,29,3137,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997,1009,1013,1019,1021,1031,1033,1039,1049,1051,1061,1063,1069,1087,1091,1093,1097,1103,1109,1117,1123,1129,1151,1153,1163,1171,1181,1187,1193,1201,1213,1217,1223]

# Our Cipher to crack
c=15012609384250219874677875435291183380996259887801084362959689829793222820134760849765791998362570297144822180464823226497176797573924507385893298639389936970609654009208449211712524653396481688098765049753795004757286133915930065553473346650316038234942894495434455505706415219264874108132945199942497009318662312261285017458955601407708432421306656177311165962626469501149556920141649893075576065182442722565993670091384298304208560718934089830554216153181578651271817639734178379386792901071212521730951208634247651506838688837039218543506015273510119988575723357218697432626850682052021919641749097620521669376865644271405225686919943046358746932323787615218639765186753354460963203088883514851667268021038592274551957739329067941888


for prime in prime_tab:
    print ("current prime : " + str(prime))
    #compute the prime'th root of C
    d = find_invpow(c,prime)

    c_bis = d ** prime
    #If it's a perfect root
    if c == c_bis:
        print("FOUND !!!!! : this is the prime : " + str(prime))
	print("This is the clear message : "+hex(d))
        break

{% endhighlight %}
<i>*I used in this script my own <a href="https://github.com/ndiab/crypto">cryptographic library</a> available on <a href="https://github.com/ndiab">github</a>.</i>

<br/><br/>
It produces the following results :
<br/><br/>
![tpctf]({{ site.url }}/assets/tpctf/crackit.png)

That means that Our C contain a 17th root and this root is : <b><i>0xe76ddb19b8abe9f382e465cf11aa364004bc</i></b>

In other word, <b>This is the clear message !</b> But we have to transcript it to human readable...

<h2> <b> II - Decode</b></h2>

Now we have the clear message in hexa, we have to decode it. In a first time, the reflex is to decoded it as an ascii like this :

![tpctf]({{ site.url }}/assets/tpctf/binascii.png)

but we can see that the results are inconclusive, furthermore I tried exactly <b>110 International encoding standards</b> without any results !

But HEY, Remember the hint ! : <i>"Look at that grammar--what a n00b. Does he even know what ASCII is?"</i>
That surely mean the encoded format is not standard !

And now we need imagination...

And I found the result not from the hexa, but from the decimal integer :
<br/>m = <b>20160320062715081415090715200318010311050428</b>

I cut this string of numbers each 2 chars like this :
<br/>m = <b>20 16 03 20 06 27 15 08 14 15 09 07 15 20 03 18 01 03 11 05 04 28</b>


And to finish, I mapped these substrings to its corresponding position in the alphabet (1 = A, 2 = B, ..., 26 = Z)

And it gave :
![tpctf]({{ site.url }}/assets/tpctf/flag.png)


<b> The flag is : tpctf{ohnoigotcracked}</b>



