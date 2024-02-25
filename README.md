# Router's Traffic Manager


## Implementare:

### Structura generala:

Am citit pentru inceput tabela de rutare corespunzatoare router-ului, urmand sa
construim apoi tria ce contine prefixele din aceasta tabela, pentru o cautare
eficienta. De asemenea, am creat si coada care stocheaza pachetele ce nu pot fi
trimise la un moment dat si asteapta deblocare.

Am impartit apoi fluxul executiei pentru fiecare pachet primit de router in
functie de rezultatele mai multor verificari facute asupra acestuia, astfel:

- Am extras adresa MAC destinatie din header-ul ethernet si am verificat daca
  pachetul ne este destinat, adica daca adresa MAC destinatie corespunde cu
  adresa MAC a interfetei pe care a fost primit pachetul, sau adresa MAC de
  broadcast

- In caz negativ, pachetul este aruncat. Altfel, extragem campul ether_type
  din acelasi header si impartim procesarea pe cele doua cazuri luate in
  calcul: pachet IPv4, respectiv pachet ARP

- Pentru pachet IPv4, verificam integritatea mesajului prin recalcularea
  checksum-ului specificat de header-ul IP. Daca acesta nu corespunde,
  pachetul este aruncat. Altfel, verificam mai departe campul TTL
  (Time To Live), caz in care fie trimitem un mesaj ICMP tip "Time to Live
  Exceeded", fie continuam cu verificarea adresei IP destinatie. Daca
  aceasta corespunde cu adresa IP a interfetei router-ului, pachetul ne
  este destinat, deci raspundem daca mesajul reprezinta un ICMP request,
  iar altfel aruncam pachetul. Daca avem de a face cu o alta adresa IP,
  ne ocupam de redirectionarea pachetului spre destinatie.
  Cautam urmatorul hop in tabela de rutare, iar daca nu il gasim trimitem
  catre expeditorul pachetului un mesaj ICMP tip "Destination Unreachable".
  Altfel, cautam adresa MAC corespondenta adresei IP a urmatorului hop gasit,
  folosind tabela dinamica ARP. Daca nu gasim un corespondent, adaugam pachetul
  in coada de asteptare si trimitem un ARP request. Altfel, trimitem pachetul
  la urmatorul hop.
  
- Pentru un pachet ARP, verificam mai intai ca ne este destinat, iar apoi,
  daca este un ARP reply adaugam noua intrare in tabela si trimitem toate
  pachetele din coada care asteptau adresa MAC furnizata de acest reply.
  Pentru ARP requests, completam adresa MAC a interfetei pe care am primit
  mesajul si il trimitem inapoi, cu modificarile aferente ale adreselor
  sursa si destinatie.

### Detalii de implementare:

Am folosit pentru LPM o structura de trie ce retine pentru fiecare nod un
index corespondent din tabela de rutare, daca nodul reprezinta finalul
unui prefix existent, dar si un camp pentru numarul de copii ai nodului.
Fiecare nod retine doi pointeri la noduri copil, corespondente unui bit de
0 sau 1.
La constructia triei, parcurgem tabela de rutare si calculam lungimea mastii,
realizam conversia campului 'prefix' din intreg in sir de caractere in
reprezentare binara, iar apoi introducem primele 'len' caractere in trie,
unde 'len' reprezinta lungimea mastii corespondente.
La cautarea urmatorului hop catre o anumita adresa IP in trie, convertim
adresa in sir de caractere si avansam bit cu bit in cautare, pana cand
nu mai avem un nod catre care sa avansam. Intoarcem index-ul din tabela de
rutare retinut de nodul la care ne-am oprit, sau -1 daca nu am gasit un
urmator hop.

Pentru tabela ARP dinamica, aceasta are capacitate nula la inceputul executiei,
urmand sa se aloce un element pentru prima intrare, urmat de dublarea
capacitatii tabelei la fiecare nevoie de realocare, pentru a face operatii de
realocare mai rar.
Cautam o adresa MAC in aceasta tabela prin simpla parcurgere liniara, functia
aferenta intorcand un indice catre intrarea portivita, sau -1 in caz ca nu s-a
gasit o corespondenta.

Pentru cazul in care nu gasim adresa MAC dorita in tabela, folosim coada de
asteptare, formata folosind functiile si structurile puse la dispozitie in
scheletul temei, ce retine elemente de tip 'Packet', structura definita pentru
a stoca toate informatiile necesare prelucrarii ulterioare a mesajului:

- indexul din tabela de rutare aferent urmatorului hop
- adresa IP a expeditorului mesajului primit de router (pentru protocolul ICMP)
- o copie a continutului bufferului primit de router
- tipul operatiei ce se va efectua asupra pachetului:
	- ICMP_ER_TYPE - ICMP Echo Request
	- ICMP_TE_TYPE - ICMP Time Limit Exceeded
	- ICMP_DU_TYPE - ICMP Destination Unreachable
	- FORWARD_TYPE - pachet in tranzit 
  toate acestea fiind macro-uri in implementare.
- lungimea copiei bufferului

De fiecare data cand primim un ARP reply, apelam functia 'send_queued_packets'
care se ocupa de trimiterea pachetelor ce pot fi deblocate. Aceasta primeste
ca argument adresa IP a carei adresa MAC este acum stiuta si parcurge coada
verificand pentru fiecare element daca pentru aceasta adresa astepta raspuns.
In caz afirmativ, se apeleaza functia corespunzatoare de trimitere in functie
de tipul de operatie. Altfel, pachetul se reintroduce in coada. Parcurgem coada
circular pana cand ajungem la o parcurgere a tuturor elementelor fara sa mai
trimitem niciun pachet.

### Constructia mesajelor:

ARP

Pentru ARP reply modificam contiutul bufferului aferent mesajului ARP request
corespunzator si il trimitem inapoi expeditorului, iar pentru ARP request
construim mesajul integral intr-un nou buffer.

ICMP

Datorita asemanarii dintre mesajele ICMP tip 'Time Limit Exceeded', respectiv
'Destination Unreachable', folosim aceeasi functie de constructie a acestor
tipuri, formand mesajul intr-un nou buffer, pas cu pas. Copiem ca payload din
mesajul initial header-ul IP, impreuna cu urmatorii 64 de biti (8 bytes) - 
dimensiunea headerului ICMP, conform documentatiei.

Pentru mesajul ICMP reply, procedam asemanator, dar copiem payload-ul primit
in ICMP request-ul corespunzator.

Folosim pentru toate cele trei cazuri functia 'prepare_icmp', care se ocupa de
constructia partilor din mesaj care nu prezinta particularitati in functie de
tip (headere, campuri cu valori standard etc.).


## Fisiere auxiliare:

'icmp_func.c/.h' - functii aferente protocolului ICMP
'arp_func.c/.h' - functii aferente protocolului ARP
'routing_func.c/.h' - functii de rutare a pachetelor, precum cele corespunzatoare
		cautarii urmatorului hop, gestionarii cozii de asteptare, functia
		de forward etc.
'util_func.c/.h' - functii auxiliare, de prelucrare a datelor


## Bibliografie:

Am folosit pentru implementarea structurii de trie un model construit la un
laborator de "Structuri de Date si Algoritmi" de anul trecut. De asemenea,
am folosit modele de pe internet pentru implementarea functiilor auxiliare
'bin_string' (de conversie a unui uint32_t in sir de caractere in reprezentare
binara), respectiv 'count_ones' (de numarare a bitilor setati pe 1 intr-un
uint32_t).
De asemenea, am folosit continutul laboratoarelor, RFC-urile si link-urile
puse la dispozitie in enuntul temei.
