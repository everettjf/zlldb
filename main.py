import lldb
import optparse
import shlex


###### Init ###### 

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f main.cmd_ztest ztest')
    debugger.HandleCommand('command script add -f main.cmd_zdebug zdebug')
    debugger.HandleCommand('command script add -f main.cmd_zdoc zdoc')

    debugger.HandleCommand('command script add -f main.cmd_zpvc zpvc')
    debugger.HandleCommand('command script add -f main.cmd_zpview zpview')

    debugger.HandleCommand('command script add -f main.cmd_zp1 zp1')
    debugger.HandleCommand('command script add -f main.cmd_zp2 zp2')
    debugger.HandleCommand('command script add -f main.cmd_zp3 zp3')
    debugger.HandleCommand('command script add -f main.cmd_zp4 zp4')
    debugger.HandleCommand('command script add -f main.cmd_zp5 zp5')

    debugger.HandleCommand('command script add -f main.cmd_zmemory zmemory')
    debugger.HandleCommand('command script add -f main.cmd_zdis zdis')
    debugger.HandleCommand('command script add -f main.cmd_zblock zblock')

    print('zlldb loaded')

###### Dev Help ###### 

def cmd_ztest(debugger, command, result, internal_dict):
    print('zlldb test')

def cmd_zdebug(debugger, command, result, internal_dict):
    import pdb; pdb.set_trace()
    print('zdebug')

def cmd_zdoc(debugger, command, result, internal_dict):
    import os
    os.system("open https://lldb.llvm.org/python_reference/lldb.{}-class.html".format(command))

###### Util ###### 

def exec_expression(interpreter, expression, print_when_noresult=None):
    res = lldb.SBCommandReturnObject()
    interpreter.HandleCommand(expression, res)
    if res.HasResult():
        print(res.GetOutput())
    else:
        if print_when_noresult is not None:
            print(print_when_noresult)

###### View / ViewController Print ###### 

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

###### Parameter Print ###### 


def cmd_zp1(debugger, command, result, internal_dict):
    interpreter = debugger.GetCommandInterpreter()
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg1', 'no result for arg1')

def cmd_zp2(debugger, command, result, internal_dict):
    interpreter = debugger.GetCommandInterpreter()
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg1', 'no result for arg1')
    exec_expression(interpreter, 'expression -O -- (char*)$arg2', 'no result for arg2')

def cmd_zp3(debugger, command, result, internal_dict):
    interpreter = debugger.GetCommandInterpreter()
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg1', 'no result for arg1')
    exec_expression(interpreter, 'expression -O -- (char*)$arg2', 'no result for arg2')
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg3', 'no result for arg3')

def cmd_zp4(debugger, command, result, internal_dict):
    interpreter = debugger.GetCommandInterpreter()
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg1', 'no result for arg1')
    exec_expression(interpreter, 'expression -O -- (char*)$arg2', 'no result for arg2')
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg3', 'no result for arg3')
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg4', 'no result for arg4')

def cmd_zp5(debugger, command, result, internal_dict):
    interpreter = debugger.GetCommandInterpreter()
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg1', 'no result for arg1')
    exec_expression(interpreter, 'expression -O -- (char*)$arg2', 'no result for arg2')
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg3', 'no result for arg3')
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg4', 'no result for arg4')
    exec_expression(interpreter, 'expression -lobjc -O -- (id)$arg5', 'no result for arg5')

###### Memory Print ######

def cmd_zmemory(debugger, command, result, internal_dict):
    cmd_args = shlex.split(command)

    usage = "usage: %prog <address> <size=8>"
    parser = optparse.OptionParser(prog='zmemory', usage=usage)
    
    try:
        (options, args) = parser.parse_args(cmd_args)
    except:
        print("error parse parameter")
        return
    
    if len(args) == 0:
        print("You need to specify the name of a variable or an address")
        return

    address = int(args[0],0)
    size = 8
    if len(args) == 2:
        size = int(args[1],0)

    print("address: 0x%x" % (address))
    print("size: 0x%x" % (size))

    interpreter = debugger.GetCommandInterpreter()
    exec_expression(interpreter, 'memory read --size %d --format x 0x%x' % (size, address), 'no result')
    

###### Disassemble ######

def cmd_zdis(debugger, command, result, internal_dict):
    cmd_args = shlex.split(command)

    usage = "usage: %prog <address> <size=8>"
    parser = optparse.OptionParser(prog='zmemory', usage=usage)
    
    try:
        (options, args) = parser.parse_args(cmd_args)
    except:
        print("error parse parameter")
        return
    
    if len(args) == 0:
        print("You need to specify the name of a variable or an address")
        return

    address = int(args[0],0)
    instruction_count = 20 
    if len(args) == 2:
        instruction_count = int(args[1],0)

    print("address: 0x%x" % (address))
    print("instruction_count: %d" % (instruction_count))

    interpreter = debugger.GetCommandInterpreter()
    disass_cmd = "disassemble --start-address 0x%x -c %d" %(address, instruction_count)
    exec_expression(interpreter, disass_cmd, 'no result')
    

###### Block ###### 

'''
struct Block_literal_1 {
    void *isa;
    int flags;
    int reserved; 
    void (*invoke)(void *, ...);
    struct Block_descriptor_1 {
        unsigned long int reserved;
        unsigned long int size;
        void (*copy_helper)(void *dst, void *src);
        void (*dispose_helper)(void *src);
        const char *signature;
    } *descriptor;
};
'''
def zblock_print_block_signature(debugger, target, process, block_address):
    pointer_size = 8 if zblock_arch_for_target_is_64bit(target) else 4
    # print("pointer size = {0}".format(pointer_size))
    # print("block address = %x"%(block_address))

    flags_address = block_address + pointer_size	# The `flags` integer is after a pointer in the struct
    
    flags_error = lldb.SBError()
    flags = process.ReadUnsignedFromMemory(flags_address, 4, flags_error)

    if not flags_error.Success():
        print("Could not retrieve the block flags")
        return
    
    block_has_signature = ((flags & (1 << 30)) != 0)	# BLOCK_HAS_SIGNATURE = (1 << 30)
    block_has_copy_dispose_helpers = ((flags & (1 << 25)) != 0) # BLOCK_HAS_COPY_DISPOSE = (1 << 25)

    
    if not block_has_signature:
        print("The block does not have a signature")
        return
    
    block_descriptor_address = block_address + 2 * 4 + 2 * pointer_size	# The block descriptor struct pointer is after 2 pointers and 2 int in the struct
    
    block_descriptor_error = lldb.SBError()
    block_descriptor = process.ReadPointerFromMemory(block_descriptor_address, block_descriptor_error)
    if not block_descriptor_error.Success():
        print("Could not read the block descriptor struct")
        return
    
    signature_address = block_descriptor + 2 * pointer_size	# The signature is after 2 unsigned int in the descriptor struct
    if block_has_copy_dispose_helpers:
        signature_address += 2 * pointer_size	# If there are a copy and dispose function pointers the signature
    
    signature_pointer_error = lldb.SBError()
    signature_pointer = process.ReadPointerFromMemory(signature_address, signature_pointer_error)
    
    signature_error = lldb.SBError()
    signature = process.ReadCStringFromMemory(signature_pointer, 255, signature_error)

    if not signature_error.Success():
        print("Could not retrieve the signature")
        return
    
    print("Signature Address: 0x%x" %(signature_address))
    print("Signature String: %s" %(signature))

    escaped_signature = signature.replace('"', '\\"')

    method_signature_cmd = 'po [NSMethodSignature signatureWithObjCTypes:"' + escaped_signature + '"]'
    debugger.HandleCommand(method_signature_cmd)

    docurl = 'https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html'
    print('Type Encodings Ref: %s' % (docurl))

def zblock_disass_block_invoke_function(debugger, target, process, block_address, instruction_count):
    pointer_size = 8 if zblock_arch_for_target_is_64bit(target) else 4
    
    invoke_function_address = block_address + pointer_size + 2 * 4	# The `invoke` function is after one pointer and 2 int in the struct
    print("Invoke address: 0x%x" % (invoke_function_address))
    
    invoke_function_error = lldb.SBError()
    invoke_function_pointer = process.ReadPointerFromMemory(invoke_function_address, invoke_function_error)
    if not invoke_function_error.Success():
        print("Could not retrieve the block invoke function pointer")
        return
    
    disass_cmd = "disassemble --start-address " + str(invoke_function_pointer) + " -c " + str(instruction_count)
    debugger.HandleCommand(disass_cmd)

def zblock_arch_for_target_is_64bit(target):
    arch_64 = ['arm64', 'x86_64']
    arch = target.GetTriple().split('-')[0]
    return arch in arch_64

def cmd_zblock(debugger, command, result, internal_dict):
    cmd_args = shlex.split(command)

    usage = "usage: %prog arg1 [--disass -d] [--number-instructions -n]"
    parser = optparse.OptionParser(prog='zblock', usage=usage)
    parser.add_option('-d', '--disass', action='store_true', dest='disass', default=False)
    parser.add_option('-n', '--number-instructions', dest='numberinstructions', default=20)
    
    try:
        (options, args) = parser.parse_args(cmd_args)
    except:
        print("error parse parameter")
        return
    
    if len(args) == 0:
        print("You need to specify the name of a variable or an address")
        return
    
    number_instructions = options.numberinstructions
    should_disass = options.disass
    
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    variable_arg = args[0]
    address = int(variable_arg,0)
    if address == 0: 
        print("invalid address")
        return

    print("Block address: 0x%x" % (address))
    
    zblock_print_block_signature(debugger, target, process, address)

    if should_disass:
        zblock_disass_block_invoke_function(debugger, target, process, address, number_instructions)
