//
//  memory.m
//  memory
//
//  Created by Jacob Fliss on 6/9/17.
//  Copyright © 2017 Jake Fliss. All rights reserved.
//

#import "memory.h"

@implementation memory

int getPIDFromName (NSString* procName){
    NSPipe *pipe = [NSPipe pipe];
    NSFileHandle *file = pipe.fileHandleForReading;
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/bin/bash";
    //NSString *getPIDCmd = [NSString stringWithFormat:@"ps -Ac -o pid,comm | awk '/^ *[0-9]+ %@$/ {print $1}'", procName];
    NSString *getPIDCmd = [NSString stringWithFormat:@"ps -A -o pid,comm | grep \"%@\" | awk '{print $1}'", procName];
    task.arguments = @[ @"-c", getPIDCmd ];
    task.standardOutput = pipe;
    
    [task launch];
    
    NSData *data = [file readDataToEndOfFile];
    [file closeFile];
    
    NSString *grepOutput = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];
    //NSLog (@"grep returned:\n%@", grepOutput);
    
    return [grepOutput intValue];
}

mach_port_t openProcess(int pid){
    mach_port_t proc = 0;
    if (task_for_pid(mach_task_self(), pid, &proc) != KERN_SUCCESS)
        return 0;
    else
        return proc;
}

unsigned char *readProcessMemory (mach_vm_address_t addr, mach_msg_type_number_t* size) {
    mach_msg_type_number_t  dataCnt = (mach_msg_type_number_t) *size;
    vm_offset_t readMem;
    
    kern_return_t kr = vm_read(proc, addr, *size, &readMem, &dataCnt);
    
    if (kr) {
        //fprintf (stderr, "Unable to read target task's memory @%p - kr 0x%x\n", (void *) addr, kr);
        return NULL;
    }
    
    return ( (unsigned char *) readMem);
}

int getAddress (NSString* addr){
    int total = 0;
    if ([addr rangeOfString:@"+"].location == NSNotFound){
        if ([addr rangeOfString:@"0x"].location != NSNotFound)
            total = [addr intValue];
        else
            total = getModuleAddress(addr);
    } else {
        NSArray *array = [addr componentsSeparatedByString:@"+"];
        for (NSString *a in array){
            if ([a rangeOfString:@"0x"].location != NSNotFound)
                total = [a intValue] + total;
            else
                total = getModuleAddress(a) + total;
        }
    }
    return total;
}

int getModuleAddress (NSString* findThis){
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(proc, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS)
    {
        mach_msg_type_number_t size = sizeof(struct dyld_all_image_infos);
        
        uint8_t* data = readProcessMemory(dyld_info.all_image_info_addr, &size);
        struct dyld_all_image_infos* infos = (struct dyld_all_image_infos *) data;
        
        mach_msg_type_number_t size2 = sizeof(struct dyld_image_info) * infos->infoArrayCount;
        uint8_t* info_addr = readProcessMemory((mach_vm_address_t) infos->infoArray, &size2);
        struct dyld_image_info* info = (struct dyld_image_info*) info_addr;
        
        for (int i=0; i < infos->infoArrayCount; i++) {
            mach_msg_type_number_t size3 = PATH_MAX;
            uint8_t* fpath_addr = readProcessMemory((mach_vm_address_t) info[i].imageFilePath, &size3);
            NSString* moduleName = @"base";
            
            if (fpath_addr){ //return if module has a name, otherwise assume is "base".
                NSString* test = [NSString stringWithUTF8String:(char *)fpath_addr];
                moduleName = [test lastPathComponent];
            }
            
            if ([moduleName isEqualToString:findThis] == 1){
                return (unsigned int)(mach_vm_address_t)info[i].imageFilePath; //found module, return address in int format.
                break;
            }
        }
        return 0; //failed
    }
    return 0; //failed
}

void listModules (){ //for debug purposes
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(proc, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS)
    {
        mach_msg_type_number_t size = sizeof(struct dyld_all_image_infos);
        
        uint8_t* data = readProcessMemory(dyld_info.all_image_info_addr, &size);
        struct dyld_all_image_infos* infos = (struct dyld_all_image_infos *) data;
        
        mach_msg_type_number_t size2 = sizeof(struct dyld_image_info) * infos->infoArrayCount;
        uint8_t* info_addr = readProcessMemory((mach_vm_address_t) infos->infoArray, &size2);
        struct dyld_image_info* info = (struct dyld_image_info*) info_addr;
        
        for (int i=0; i < infos->infoArrayCount; i++) {
            mach_msg_type_number_t size3 = PATH_MAX;
            uint8_t* fpath_addr = readProcessMemory((mach_vm_address_t) info[i].imageFilePath, &size3);
            NSString* moduleName = @"base";
            
            if (fpath_addr){ //return if module has a name, otherwise assume is "base".
                NSString* test = [NSString stringWithUTF8String:(char *)fpath_addr];
                moduleName = [test lastPathComponent];
            }
            
            printf("0x%02x %s", (unsigned int)(mach_vm_address_t)info[i].imageFilePath, [moduleName UTF8String]);
        }
    }
}

vm_offset_t DumpMemory(NSString *address, mach_msg_type_number_t size)
{
    vm_offset_t dumpRegion = 0;
    vm_address_t addr = getAddress(address);
    mach_vm_read(proc, addr, sizeof(uint32_t), &dumpRegion, &size);
    return dumpRegion;
}

bool IsLetterOrDigit(unichar t){
    if(t>='0' && t<='9')
        return true;
    else
        return false;
}

NSMutableArray* dumpRegion;
vm_address_t dumpAddress;

vm_address_t AoBScan(NSString *address, int length, NSString *code)
{
    //we need to step through the pages in memory. (https://stackoverflow.com/questions/1627998/retrieving-the-memory-map-of-its-own-process-in-os-x-10-5-10-6)
    kern_return_t kr;

    vm_size_t vmsize;
    vm_address_t addr;
    vm_region_basic_info_data_t info;
    mach_msg_type_number_t info_count;
    vm_region_flavor_t flavor;
    memory_object_name_t object;
    NSMutableDictionary *addrsNLength = [NSMutableDictionary dictionary];
    
    do {
        flavor = VM_REGION_BASIC_INFO;
        info_count = VM_REGION_BASIC_INFO_COUNT;
        kr = vm_region(proc, &addr, &vmsize, flavor, (vm_region_info_t)&info, &info_count, &object);
        if (kr == KERN_SUCCESS && (info.protection & VM_PROT_WRITE)) { //if it's writable
            if (address.intValue < addr && addr < (address.intValue + length)) //needs to be tested
                [addrsNLength setObject: [NSString stringWithFormat:@"%lu", vmsize]  forKey: [NSString stringWithFormat:@"%lu", addr]];
            addr += vmsize;
        }
        else if (kr != KERN_INVALID_ADDRESS) {
            if (proc != MACH_PORT_NULL)
                mach_port_deallocate(mach_task_self(), proc);
        }
    } while (kr != KERN_INVALID_ADDRESS);
    
    //now build our byte array and mask
    NSArray *stringByteArray = [code componentsSeparatedByString:@" "]; //our AoB in string format
    NSMutableArray *myPattern; //our AoB in byte format
    NSString *mask = NULL; //our mask
    int i = 0;
    for (NSString *ba in stringByteArray)
    {
        unichar firstChar = [ba characterAtIndex:0];
        unichar secondChar = [ba characterAtIndex:1];
        if ([ba isEqual: @"??"])
        {
            myPattern[i] = [@"0xFF" dataUsingEncoding:NSUTF8StringEncoding];
            [mask stringByAppendingString:@"?"];
        }
        else if (IsLetterOrDigit(firstChar) && secondChar == '?') //partial match
        {
            myPattern[i] = [[NSString stringWithFormat:@"%s%hu%s", "0x", firstChar, "F"] dataUsingEncoding:NSUTF8StringEncoding];
            [mask stringByAppendingString:@"?"]; //show it's still a wildcard of some kind
        }
        else if (IsLetterOrDigit(secondChar) && firstChar == '?') //partial match
        {
            myPattern[i] = [[NSString stringWithFormat:@"%s%hu", "0xF", secondChar] dataUsingEncoding:NSUTF8StringEncoding];
            [mask stringByAppendingString:@"?"]; //show it's still a wildcard of some kind
        }
        else
        {
            myPattern[i] = [ba dataUsingEncoding:NSUTF8StringEncoding];
            [mask stringByAppendingString:@"x"];
        }
        i++;
    }
    
    for (NSString* key in addrsNLength) { //search through the pages dictionary to find our AoB
        id value = [addrsNLength objectForKey:key];
        DumpMemory(key,value);
        vm_address_t theAddr = FindPattern(myPattern, mask, 0);
        if (theAddr > 0) return theAddr; //success
    }
    
    return 0; //failed
}

vm_address_t FindPattern(NSMutableArray* btPattern, NSString *strMask, int nOffset)
{
        if (strMask.length != [btPattern count])
            return 0;
        
        for (int x = 0; x < (sizeof dumpRegion); x++)
        {
            if (MaskCheck(x, btPattern, strMask))
            {
                return ((int)dumpAddress + (x + nOffset));
            }
        }
        return 0;
}

bool MaskCheck(int nOffset, NSMutableArray* btPattern, NSString *strMask)
{
    // Loop the pattern and compare to the mask and dump.
    for (int x = 0; x < [btPattern count]; x++)
    {
        // If the mask char is a wildcard.
        if ([strMask characterAtIndex:x] == '?')
        {
            if ((int)btPattern[x] == 0xFF) //100% wildcard
                continue;
            else
            { //50% wildcard
                if ([dumpRegion[nOffset + x] count] == 2) //byte must be 2 characters long
                {
                    id test = [NSNumber numberWithInteger:x];
                    if ([[NSString stringWithFormat:@"%lu", (unsigned long)[btPattern indexOfObject:test]] characterAtIndex:0] == '?') { //ex: ?5
                        if ([dumpRegion[nOffset + x] characterAtIndex:1] != [btPattern indexOfObject:test])
                            return false;
                    }
                    else if ([[NSString stringWithFormat:@"%lu", (unsigned long)[btPattern indexOfObject:test]] characterAtIndex:1] == '?') //ex: 5?
                    {
                        if ([dumpRegion[nOffset + x] characterAtIndex:0] != [btPattern indexOfObject:test])
                            return false;
                    }
                }
            }
        }
        
        // If the mask char is not a wildcard, ensure a match is made in the pattern.
        if (([strMask characterAtIndex:x] == 'x') && (btPattern[x] != dumpRegion[nOffset + x]))
            return false;
    }
    
    // The loop was successful so we found 1 pattern match.
    return true;
}

int readInt32 (NSString *address){
    return *(int *)DumpMemory(address, 4);
}

float readFloat (NSString *address){
    return *(float *)DumpMemory(address, 4);
}

long readLong (NSString *address){ //64bit values
    return *(long *)DumpMemory(address, 16);
}

NSString* readString (NSString *address){
    return [NSString stringWithFormat: @"%lu", DumpMemory(address, address.length)];
}

void writeMemory (NSString *address, NSString *type, NSString *newVal){
    vm_address_t addr = getAddress(address);
    
    if ([type isEqual: @"int"] || [type isEqual: @"byte"]){
        int tVal = newVal.intValue;
        mach_vm_write(proc, addr, (vm_offset_t)&tVal, sizeof(tVal));
    } else if ([type isEqual: @"float"]){
        float tVal = newVal.floatValue;
        mach_vm_write(proc, addr, (vm_offset_t)&tVal, sizeof(tVal));
    } else if ([type isEqual: @"string"]){
        mach_vm_write(proc, addr, (vm_offset_t)&newVal, sizeof(newVal));
    } else if ([type isEqual: @"bytes"]){
        NSArray *stringByteArray = [newVal componentsSeparatedByString:@" "];
        int c = stringByteArray.count;
        NSInteger myPattern[c];
        for (int i = 0; i < c; i++)
        {
            myPattern[i] = [stringByteArray[i] intValue];
        }
        mach_vm_write(proc, addr, (vm_offset_t)&myPattern, sizeof(c));
    }
    
}

@end
