use std::io::File;
use std::hashmap::HashMap;

fn main() {
    compile();
}

enum CPoolEntry {
    UTF8(~str),                     // value
    INTEGER(i32),                   // value
    FLOAT(f32),                     // value
    LONG(i64),                      // value
    DOUBLE(f64),                    // value
    CLASS(u16),                     // name_ref 
    STRING(u16),                    // content_ref
    FIELD_REF(u16, u16),            // class_ref, name_any_type
    METHOD_REF(u16, u16),           // class_ref, name_and_type
    INTERFACE_METHOD_REF(u16, u16), // class_ref, name_and_type
    NAME_AND_TYPE(u16, u16),        // name_ref, type_ref
    METHOD_HANDLE(u8, u16),         // kind, reference
    METHOD_TYPE(u16),               // descriptor_ref
    INVOKE_DYNAMIC(u16, u16)        // bootstrep_idx, name_and_type
}

struct CPool {
    entries: ~[CPoolEntry],
    next_idx: u16,
    kv_map: ~HashMap<uint, uint>,
    vk_map: ~HashMap<uint, uint>
}

impl CPool {
    fn new() -> CPool {
        CPool {entries: ~[], next_idx: 1, kv_map: ~HashMap::<uint, uint>::new(), vk_map: ~HashMap::<uint, uint>::new()}
    }

    fn add_entry(&mut self, entry: CPoolEntry) {

    }
}



fn compile() {
    let mut file = File::create(&Path::new("CompilerTest.class"));
    let minor = 0;
    let major = 51;
    
    file.write_be_u32(0xCAFEBABE);
    file.write_be_u16(minor);
    file.write_be_u16(major);
    
    file.write_be_u16(12); // Entries in constantpool

    // 1: Str: <init> method name
    let init_name = "<init>";
    file.write_u8(1); 
    file.write_be_u16(init_name.len() as u16);
    file.write_str(init_name);

    // 2: Str: <init> method signature
    let init_sig = "()V";
    file.write_u8(1);
    file.write_be_u16(init_sig.len() as u16);
    file.write_str(init_sig);

    // 3: Str: <init> origin class
    let obj_name = "java/lang/Object";
    file.write_u8(1);
    file.write_be_u16(obj_name.len() as u16);
    file.write_str(obj_name);

    // 4: Str: main method name
    let main_name = "main";
    file.write_u8(1);
    file.write_be_u16(main_name.len() as u16);
    file.write_str(main_name);

    // 5: Str: main method signature
    let main_sig = "([Ljava/lang/String;)V";
    file.write_u8(1);
    file.write_be_u16(main_sig.len() as u16);
    file.write_str(main_sig);

    // 6: Str: main method origin class
    let comptest_name = "CompilerTest";
    file.write_u8(1);
    file.write_be_u16(comptest_name.len() as u16);
    file.write_str(comptest_name);

    // 7: NameAndType: <init>
    file.write_u8(12);
    file.write_be_u16(1);   // Ref to first entry
    file.write_be_u16(2);   // Ref to second entry

    // 8: Class: Object
    file.write_u8(7);
    file.write_be_u16(3);   // Ref to third entry

    // 9: Class: CompilerTest
    file.write_u8(7);
    file.write_be_u16(6);   // Ref to sixth entry

    // 10: Method ref: <init>
    file.write_u8(10);
    file.write_be_u16(8);
    file.write_be_u16(7);

    // 11: String: Code
    file.write_u8(1);
    file.write_be_u16(4);
    file.write_str("Code");


    file.write_be_u16(0x0020 | 0x0001); // public super
    file.write_be_u16(9);   // Ref to 9th entry: this class
    file.write_be_u16(8);   // Ref to 8th entry: super class

    file.write_be_u16(0);   // No interfaces
    file.write_be_u16(0);   // No fields
    file.write_be_u16(2);   // 2 Methods

    // Method 1: <init>
    file.write_be_u16(0);   // No accflags
    file.write_be_u16(1);   // Ref to cpool #1
    file.write_be_u16(2);   // Ref to cpool #2
    file.write_be_u16(1);   // 1 attr
    file.write_be_u16(11);  // Ref to cpool #11
    file.write_be_u32(17);  // 29 bytes followng

    // Code attr for <init>
    file.write_be_u16(1);   // Max stack depth 1
    file.write_be_u16(1);   // Max locals 1
    file.write_be_u32(5);   // 5 bytes of code
    file.write_u8(0x2a);    // aload_0
    file.write_u8(0xb7);    // invokestatic
    file.write_u8(0x00);
    file.write_u8(0x0a);    // #10
    file.write_u8(0xb1);    // return
    file.write_be_u16(0);   // no exception handlers
    file.write_be_u16(0);   // No attr count
    // ???

    // Method 2: main
    file.write_be_u16(0x0001 | 0x0008);
    file.write_be_u16(4);
    file.write_be_u16(5);
    file.write_be_u16(1);
    file.write_be_u16(11);
    file.write_be_u32(13);

    // Code attr for main
    file.write_be_u16(1);   // Max stack depth 1
    file.write_be_u16(1);   // Max locals 1
    file.write_be_u32(1);   // 5 bytes of code
    file.write_u8(0xb1);    // return
    file.write_be_u16(0);   // no exception handlers
    file.write_be_u16(0);   // No attributes
    // ???

    // No classfile attributes
    file.write_be_u16(0);

    file.flush();
}