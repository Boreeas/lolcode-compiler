use std::io::File;
use std::hashmap::HashMap;
use std::to_bytes::ToBytes;

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
    kv_map: ~HashMap<uint, u16>,
    vk_map: ~HashMap<u16, uint>
}

impl CPool {
    fn new() -> CPool {
        CPool {
            entries: ~[], next_idx: 1, 
            kv_map: ~HashMap::<uint, u16>::new(), 
            vk_map: ~HashMap::<u16, uint>::new()
        }
    }

    fn add_entry(&mut self, entry: CPoolEntry) {
        let increment = match entry {
            LONG(_) | DOUBLE(_) => 2,
            _                   => 1
        };

        self.entries.push(entry);
        self.kv_map.insert(self.entries.len() - 1, self.next_idx);
        self.vk_map.insert(self.next_idx, self.entries.len() - 1);
        self.next_idx += increment;
    }

    fn get<'a>(&'a self, idx: uint) -> &'a CPoolEntry {
        &self.entries[idx]
    }

    fn vec_to_pool<'a>(&'a self, vec_idx: &uint) -> &'a u16 {
        self.kv_map.get(vec_idx)
    }

    fn pool_to_vec<'a>(&'a self, pool_idx: &u16) -> &'a uint {
        self.vk_map.get(pool_idx)
    }

    fn to_vec(&self) -> ~[u8] {
        let mut buf = ~[];

        buf.push_all(self.next_idx.to_bytes(false));

        for entry in self.entries.iter() {
            match entry {
                &UTF8(ref val)  => {
                    buf.push(1);
                    buf.push_all((val.len() as u16).to_bytes(false));
                    let str_bytes = val.to_bytes(false);
                    buf.push_all(str_bytes.slice(0, str_bytes.len() - 1));
                },
                &INTEGER(val)   => {
                    buf.push(3);
                    buf.push_all(val.to_bytes(false));
                },
                &FLOAT(val)     => {
                    buf.push(4);
                    buf.push_all(val.to_bytes(false));
                },
                &LONG(val)      => {
                    buf.push(5);
                    buf.push_all(val.to_bytes(false));
                },
                &DOUBLE(val)    => {
                    buf.push(6);
                    buf.push_all(val.to_bytes(false));
                },
                &CLASS(ref_idx) => {
                    buf.push(7);
                    buf.push_all(ref_idx.to_bytes(false));
                },
                &STRING(ref_idx) => {
                    buf.push(8);
                    buf.push_all(ref_idx.to_bytes(false));
                },
                &FIELD_REF(class_ref, name_and_type) => {
                    buf.push(9);
                    buf.push_all(class_ref.to_bytes(false));
                    buf.push_all(name_and_type.to_bytes(false));
                },
                &METHOD_REF(class_ref, name_and_type) => {
                    buf.push(10);
                    buf.push_all(class_ref.to_bytes(false));
                    buf.push_all(name_and_type.to_bytes(false));
                },
                &INTERFACE_METHOD_REF(class_ref, name_and_type) => {
                    buf.push(11);
                    buf.push_all(class_ref.to_bytes(false));
                    buf.push_all(name_and_type.to_bytes(false));
                },
                &NAME_AND_TYPE(name_ref, type_ref) => {
                    buf.push(12);
                    buf.push_all(name_ref.to_bytes(false));
                    buf.push_all(type_ref.to_bytes(false));
                },
                &METHOD_HANDLE(kind, ref_idx) => {
                    buf.push(15);
                    buf.push(kind);
                    buf.push_all(ref_idx.to_bytes(false));
                },
                &METHOD_TYPE(descriptor_ref) => {
                    buf.push(16);
                    buf.push_all(descriptor_ref.to_bytes(false));
                },
                &INVOKE_DYNAMIC(bootstrap_idx, name_and_type) => {
                    buf.push(18);
                    buf.push_all(bootstrap_idx.to_bytes(false));
                    buf.push_all(name_and_type.to_bytes(false));
                }
            }
        };

        buf
    }
}



fn compile() {
    let mut file = File::create(&Path::new("CompilerTest.class"));
    let minor = 0;
    let major = 51;
    
    file.write_be_u32(0xCAFEBABE);
    file.write_be_u16(minor);
    file.write_be_u16(major);

    let mut cpool = CPool::new();
    cpool.add_entry(UTF8(~"<init>"));
    cpool.add_entry(UTF8(~"()V"));
    cpool.add_entry(UTF8(~"java/lang/Object"));
    cpool.add_entry(UTF8(~"main"));
    cpool.add_entry(UTF8(~"([Ljava/lang/String;)V"));
    cpool.add_entry(UTF8(~"CompilerTest"));
    cpool.add_entry(NAME_AND_TYPE(1, 2));
    cpool.add_entry(CLASS(3));
    cpool.add_entry(CLASS(6));
    cpool.add_entry(METHOD_REF(8, 7));
    cpool.add_entry(UTF8(~"Code"));

    file.write(cpool.to_vec());

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