# zlldb

## install

1. git clone `git@github.com:everettjf/zlldb.git`
2. add `command script import ~/zlldb/main.py` into `~/.lldbinit`

## command list

```
zpvc
zpview

zp1 : print oc arg1
zp2 : print oc arg1,arg2
zp3
zp4
zp5

zmemory <address> <format-size>
zdis <address> <instruction-count>
zblock <block-address> : print oc block signature, parameter -d for disassemble

zdoc SBTarget
ztest
```

## ref

- https://github.com/4ch12dy/xia0LLDB
- https://github.com/ddeville/block-lldb-script 
- https://github.com/facebook/chisel 
- https://github.com/DerekSelander/LLDB
- https://github.com/ddeville/block-lldb-script

