#!/usr/bin/env python2

from sympy import Symbol, solve
import math

a = 62791383142154
r = 1.940035480806554e13
R = 4.777053952827391e13

sinA = a / (2 * R)
cosA = math.sqrt(1 - sinA * sinA)
# b^2 + c^2 - 2bc cosA = a^2
# r = bcsinA / (a + b + c)

# let u = b + c, v = bc
# u^2 - 2v - 2vcosA = a^2
# vsinA / (a + u) = r

u = Symbol('u')
v = r * (a + u) / sinA
u = solve(u * u - 2 * (1 + cosA) * v - a * a, u)[1]
print(u)
v = r * (a + u) / sinA

t = math.sqrt(u * u - 4 * v)
c = (u + t) / 2
b = u - c
print(b, c)
print("flag{" + "{}-{}-{}".format(hex(a)[2:], hex(int(b))[2:], hex(int(c))[2:]) + "}")

# flag{391bc2164f0a-4064e4798769-56e0de138176}
