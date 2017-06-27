---
layout: post
title:  "Write UP - NDH XV Wargame  : Unlucky [CRYPTO]"
date:   2017-06-26 19:42:27 +0200
categories: CTF-WriteUp
---

![ndhXV]({{ site.url }}/assets/nuit_hack_XV_2017.jpg)

Cet article a pour but de présenter la résolution du challenge CRYPTO unlucky présenté à la quinzième édition de la <a href="https://nuitduhack.com"> nuit du hack </a>. Ce challenge n'a pas été résolu lors de la wargame (du moins dans le temps imparti) et était récompensé de 350 points.
<br/>


<h2> <b>Présentation de l'épreuve </b></h2>

L'épreuve se présente sous forme d'un fichier texte

![unlucky]({{ site.url }}/assets/unlucky.png)

Contenant une clé publique d’un serveur 32 bits avec Go 1.5.1, un message chiffré avec cette clé publique (le message que nous devrons déchiffrer) ainsi que 61 signatures du serveur interceptés avec le clair correspondant.
L’algorithme de chiffrement utilisé ici est RSA avec des clés 4096 bits, ne présentant à première vue aucun signe de faiblesse.

<h2><b>CVE-2015-8618</b></h2>
Je remercie mon partenaire <a href="https://twitter.com/0xBytemare">@0xBytemare</a> de m’avoir rapidement trouvé cette <a href = "http://www.openwall.com/lists/oss-security/2016/01/13/7">CVE</a> concernant une mise à jour de sécurité de Go v1.5.3.
En effet, la vulnérabilité publiée en 2015 concerne une bibliothèque de mathématique de Go (math/big) qui est utilisée pour le chiffrement RSA. Celle ci a la probabilité d’effectuer une erreur de calcul de 1/2^26 (1 fois sur 64 millions) sur une architecture 32 bits. Si cette erreur intervient lors d’un chiffrement RSA_CRT, cela pourrait permettre à un attaquant d’en déduire la clé privée (Détails expliqués plus bas). La CVE n'en dit pas plus quant à son exploitation, aucun POC n'est trouvable sur le net.

Cette CVE correspond parfaitement à notre scénario, afin de pouvoir l’exploiter, il va donc falloir dans un premier temps trouver une signature qui a échouée.
<br/><br/>


<h2><b>Un peu de maths</b></h2>
<h3>&emsp;&emsp;RSA_CRT</h3>
