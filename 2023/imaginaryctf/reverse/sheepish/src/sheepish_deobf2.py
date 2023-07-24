tru = (lambda x10:lambda x5:x10)
fls = (lambda x10:lambda x5:x5)

fst = (lambda x01:x01(tru))
snd = (lambda x01:x01(fls))

is0 = (lambda x10:x10(lambda x01:(fls))(tru))
pair = (lambda x10:lambda x5:lambda x14:x14(x10)(x5))


power = (lambda x10:lambda x5:x5(x10))
succ = (lambda x2:lambda x10:lambda x5:x10(x2(x10)(x5)))
pred = (lambda x2:lambda x13:lambda x3:x2(lambda x12:lambda x9:x9(x12(x13)))(lambda x01:x3)(lambda x10:x10))
plus = (lambda x10:lambda x5:x10(succ)(x5))
minus = (lambda x10:lambda x5:x5(pred)(x10))
le = (lambda x10:lambda x5:is0(minus(x10)(x5)))
ge = (lambda x10:lambda x5:is0(minus(x5)(x10)))
mult = (lambda x10:lambda x5:lambda x14:x10(x5(x14)))
two = (lambda x10:lambda x5:x10(x10(x5)))
three = (lambda x10:lambda x5:x10(x10(x10(x5))))
four = (succ)(three)


def print_and_return(x):
    print(x)
    return x

print((((lambda x13:((lambda x3:x13(lambda x7:x3(x3)(x7)))(lambda x3:x13(lambda x7:x3(x3)(x7))))) (lambda x13:lambda x11:lambda x6:fst(x11) (lambda x01:(tru)) (lambda x01:(lambda x10:lambda x5:x10(x5)(fls))((lambda x10:lambda x5:(lambda x10:lambda x5:x10(x5)(fls)) (ge(x10)(x5))(le(x10)(x5)))((lambda x4:fst(snd(x4)))(x11))((lambda x4:fst(snd(x4)))(x6)))(x13((lambda x4:snd(snd(x4)))(x11))((lambda x4:snd(snd(x4)))(x6))))(tru))) ((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4))) ((lambda x4:lambda x3:pair(fls)(pair(x3)(x4))) ((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4))) ((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))((lambda x4:lambda x3:pair(fls)(pair(x3)(x4))) ((lambda x4:lambda x3:pair(fls)(pair(x3)(x4))) (pair(tru)(tru)) ((plus) (mult((power)(two)(four))(succ(mult(two)(three)))) ((plus)(mult (two) (three))(succ(mult(two)(three)))))) ((plus)(mult((power)(two)(four))(three))(mult((plus)(two)(three))(three))))((plus)(mult((power)(two)(four))(four))(fls)))((plus)(mult((power)(two)(four))(four))(fls)))((plus)(mult((power)(two)(four))(four))(fls)))((plus)(mult((power)(two)(four))(mult(two)(three)))(two)))((plus)(mult((power)(two)(four))((plus)(two)(three)))(mult((plus)(two)(three))(three))))((plus)(mult((power)(two)(four))(succ(mult(two)(three))))(fls)))((plus)(mult((power)(two)(four))(three))(three)))((plus)(mult((power)(two)(four))(three))(three)))((plus)(mult((power)(two)(four))(mult(two)(three)))(mult(four)(two))))((plus)(mult((power)(two)(four))(succ(mult(two)(three))))(three)))((plus)(mult((power)(two)(four))((plus)(two)(three)))(mult((plus)(two)(three))(three))))((plus)(mult((power)(two)(four))(three))(fls)))((plus)( mult((power)(two)(four)) (mult(two)(three)) )(four)))((plus)(mult((power)(two)(four))(succ(mult(two)(three))))((plus)(succ(mult(two)(three)))(four))))((plus)(mult((power)(two)(four))(mult(two)(three)))(mult(two)(three))))((plus)(mult((power)(two)(four))(succ(mult(two)(three))))(four)))((plus)(mult((power) (two) (four))(mult(two)(three)))(three)))((plus)(mult((power)(two)(four))(mult(two)(three)))((power)(three)(two)))) (((lambda x13:((lambda x3:x13(lambda x7:x3(x3)(x7)))(lambda x3:x13(lambda x7:x3(x3)(x7)))))(lambda x13:(lambda x8:(((lambda x4:lambda x3:pair(fls)(pair(x3)(x4)))(x13(print_and_return(x8[1:])))(((lambda x13:((lambda x3:x13(lambda x7:x3(x3)(x7)))(lambda x3:x13(lambda x7:x3(x3)(x7)))))(lambda x13:(lambda x2:((succ(x13(x2-1))) if print_and_return(x2) else (fls)))))(x8[0]))) if len(x8) else (pair(tru)(tru))))))(input(">>> ").encode())))("Well done!")("Try again..."))
