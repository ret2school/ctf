# [BreizhCTF2020 - Reverse] L'appli secrète du breizhCTF

    Value: 131

    Description:

    En arrivant à Rennes au BreizhCTF, vous avez trouvé un téléphone par terre et avez décidé de le garder avec vous. Vous vous rendez compte que sur ce téléphone, il y a une appli 'SuperSecretApp'.

    Malheureusement, pour accéder à son contenu, vous devez avoir la bonne combinaison du username et du password.

    Vous avez donc décidé de reverse l'application pour trouvez cela!

    Auteur: Worty

    Format : BZHCTF{username-password}

The file provided is an `.apk`, we extract the source code with the `apktool` tool:

In the folder ``Sourcescomexample\supersecretapp\data\`, we find the file containing all the logic of the application:

```java
/*
 * Location:
 * \sources\com\example\supersecretapp\data\LoginDataSource.java
*/


package com.example.supersecretapp.data;

import com.example.supersecretapp.data.Result;
import com.example.supersecretapp.data.model.LoggedInUser;
import java.io.IOException;
import java.util.UUID;
import kotlin.text.Typography;

public class LoginDataSource {
    public boolean verifiedPassword(String pwd) {
        if (((char) (pwd.charAt(0) ^ "!".charAt(0))) != "@".charAt(0) || (pwd.charAt(1) ^ "m".charAt(0)) + Typography.dollar != 120 || ((char) (pwd.charAt(0) ^ pwd.charAt(2))) != "[".charAt(0) || pwd.charAt(3) != "V".charAt(0)) {
            return false;
        }
        if ((pwd.charAt(pwd.length() % 4) ^ pwd.charAt(4)) + 'b' != "e".charAt(0) || ((char) (pwd.charAt(5) + 7)) != "T".charAt(0) || ((char) ((pwd.charAt(6) & 255) ^ 16)) != "h".charAt(0)) {
            return false;
        }
        if (pwd.charAt(7) == ((char) (pwd.charAt(5) ^ pwd.charAt(2)))) {
            return true;
        }
        return false;
    }

    public Result<LoggedInUser> login(String username, String password) {
        if (username.length() != 15 || password.length() != 8) {
            return new Result.Error(new IOException("Error logging in"));
        }
        if (!username.equals("kalucheAdmin:))")) {
            return new Result.Error(new IOException("Error logging in"));
        }
        if (verifiedPassword(password)) {
            return new Result.Success(new LoggedInUser(UUID.randomUUID().toString(), "Well done!"));
        }
        return new Result.Error(new IOException("Error logging in"));
    }

    public void logout() {
    }
}
```

We can see that the `login` function is used to check that our user name is indeed `kalucheAdmin:))`.

As for the password which is managed by the `verifiedPassword` function, I decide to use `z3`:
```python
#!/usr/bin python3

from z3 import *

# List of BitVec
passwd = [BitVec(f'{i}', 8) for i in range(8)]
s = Solver()

# Constraints

# pwd.charAt(0) ^ "!".charAt(0) != "@".charAt(0)
s.add( (passwd[0] ^ ord("!") ) == ord("@") )

# pwd.charAt(1) ^ "m".charAt(0)) + Typography.dollar != 120
s.add( (passwd[1] ^ ord("m")) + ord("$") == 120 )

#(pwd.charAt(0) ^ pwd.charAt(2)) != "[".charAt(0)
s.add( passwd[0] ^ passwd[2] == ord("[") )

# pwd.charAt(3) != "V".charAt(0)
s.add( passwd[3] == ord("V") )

# pwd.charAt(pwd.length() % 4) ^ pwd.charAt(4)) + 'b' != "e".charAt(0)
# pwd.charAt(0) ^ pwd.charAt(4)) + 'b' != "e".charAt(0)
s.add( (passwd[0] ^ passwd[4]) + ord("b") == ord("e") )

# pwd.charAt(5) + 7 != "T".charAt(0
s.add( (passwd[5] + 7)  == ord("T") )

# ((pwd.charAt(6) & 255) ^ 16) != "h".charAt(0)
s.add( ((passwd[6] &  255) ^ 16)  == ord("h") )

# pwd.charAt(7) == ((char) (pwd.charAt(5) ^ pwd.charAt(2)))
s.add( passwd[7] == (passwd[5] ^ passwd[2]) )

print(s.check())
model = s.model()
flag = ''.join([chr(int(str(model[passwd[i]]))) for i in range(len(model))])
print(flag)
```

The password is then obtained:
```
> python3 solve.py
sat
a9:VbMxw
```

So the flag is:
```
BZHCTF{kalucheAdmin-a9:VbMxw}
```