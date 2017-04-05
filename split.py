#!/usr/bin/env python
str = raw_input()
for i in range(0, len(str), 80):
	print "\'%s\' \\" % str[i:i+80]

