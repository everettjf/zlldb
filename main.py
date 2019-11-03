

import lldb

def cmd_ztest(debugger, command, result, internal_dict):
    import pdb; pdb.set_trace()
    print('zztest')

def cmd_zdoc(debugger, command, result, internal_dict):
    import os; 
    os.system("open https://lldb.llvm.org/python_reference/lldb.{}-class.html".format(command))

def cmd_zpvc(debugger, command, result, internal_dict):
    # expression -lobjc -O -- [UIViewController _printHierarchy]
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter() 
    expression = 'expression -lobjc -O -- [UIViewController _printHierarchy]'
    interpreter.HandleCommand(expression, res)
    if res.HasResult(): 
        print(res.GetOutput())
    else:
        print('No result')

def cmd_zpview(debugger, command, result, internal_dict):
    # expression -lobjc -O -- [(id)[[UIApplication sharedApplication] keyWindow] recursiveDescription]
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter() 
    expression = 'expression -lobjc -O -- [(id)[[UIApplication sharedApplication] keyWindow] recursiveDescription]'
    interpreter.HandleCommand(expression, res)
    if res.HasResult(): 
        print(res.GetOutput())
    else:
        print('No result')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f main.cmd_ztest ztest')
    debugger.HandleCommand('command script add -f main.cmd_zdoc zdoc')
    debugger.HandleCommand('command script add -f main.cmd_zpvc zpvc')
    debugger.HandleCommand('command script add -f main.cmd_zpview zpview')
    print('zz loaded')
