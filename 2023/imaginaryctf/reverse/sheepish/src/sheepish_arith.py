def plus(x):
    return lambda y: x + y

def mult(x):
    return lambda y: x * y

def power(x):
    return lambda y: x ** y

def succ(x):
    return x+1

zero = 0
two = 2
three = 3
four = 4

flag = ""

flag += chr(((plus)(mult((power)(two)(four))(succ(mult(two)(three)))) ((plus)(mult (two) (three))(succ(mult(two)(three))))))
flag += chr(((plus)(mult((power)(two)(four))(three))(mult((plus)(two)(three))(three))))
flag += chr(((plus)(mult((power)(two)(four))(four))(zero)))
flag += chr(((plus)(mult((power)(two)(four))(four))(zero)))
flag += chr(((plus)(mult((power)(two)(four))(four))(zero)))
flag += chr(((plus)(mult((power)(two)(four))(mult(two)(three)))(two)))
flag += chr(((plus)(mult((power)(two)(four))((plus)(two)(three)))(mult((plus)(two)(three))(three))))
flag += chr(((plus)(mult((power)(two)(four))(succ(mult(two)(three))))(zero)))
flag += chr(((plus)(mult((power)(two)(four))(three))(three)))
flag += chr(((plus)(mult((power)(two)(four))(three))(three)))
flag += chr(((plus)(mult((power)(two)(four))(mult(two)(three)))(mult(four)(two))))
flag += chr(((plus)(mult((power)(two)(four))(succ(mult(two)(three))))(three)))
flag += chr(((plus)(mult((power)(two)(four))((plus)(two)(three)))(mult((plus)(two)(three))(three))))
flag += chr(((plus)(mult((power)(two)(four))(three))(zero)))
flag += chr(((plus)( mult((power)(two)(four)) (mult(two)(three)) )(four)))
flag += chr(((plus)(mult((power)(two)(four))(succ(mult(two)(three))))((plus)(succ(mult(two)(three)))(four))))
flag += chr(((plus)(mult((power)(two)(four))(mult(two)(three)))(mult(two)(three))))
flag += chr(((plus)(mult((power)(two)(four))(succ(mult(two)(three))))(four)))
flag += chr(((plus)(mult((power) (two) (four))(mult(two)(three)))(three)))
flag += chr(((plus)(mult((power)(two)(four))(mult(two)(three)))((power)(three)(two))))

print(flag[::-1])
