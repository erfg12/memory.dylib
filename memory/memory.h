//
//  memory.h
//  memory
//
//  Created by Jacob Fliss on 6/9/17.
//  Copyright © 2017 Jake Fliss. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <mach/vm_map.h>

mach_port_t proc;
int getPIDFromName (NSString* procName);
void writeMemory (NSString* address, NSString* type, NSString* newVal);
int readInt32 (NSString* address);
float readFloat (NSString* address);
long readLong (NSString* address);
NSString* readString (NSString *address);
mach_port_t openProcess(int pid);
int getModuleAddress(NSString* findThis);
vm_offset_t DumpMemory(NSString *address, mach_msg_type_number_t size);
void listModules ();
vm_address_t AoBScan(NSString *address, int length, NSString *code);

@interface memory : NSObject


@end
