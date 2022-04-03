# [BreizhCTF2020 - Prog] PYCTHON
    Description:

    Nous n'arrivons pas à retrouver l'information cachée à partir de ce fichier...

    Auteur: T0fix
    
    Format : BZHCTF{}

    Task: pycthon.cpython-38.pyc

The provided file is a `.pyc` which contains compiled pseudo-code for a program written in Python.

You just have to use the `uncompyle6` package with the following command: `uncompyle6 -o .pycthon.cpython-38.pyc`

We obtain then, the source python code:

```python
def hoflag():
    tab = [
     'U', 'n', 'c', '0', 'm', 'p', 'y', 'l', '3', 'd', '_', 'P', 'y', 't', 'h', '0', 'n', '_', 'f', '1', 'l', 'E']
    flag = ''.join(tab)
    print('Well done, the flag is --> BZHCTF{' + flag + '}')

def welcome(hello):
    print(hello)

welcome('WELCOME TO BREIZHCTF mate!')
print('Try to get my flag')
hoflag()
```

All that is left to do is to execute the source code:

```
BZHCTF{Unc0mpyl3d_Pyth0n_f1lE}
```