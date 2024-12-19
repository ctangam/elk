use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use mmap::{MapOption, MemoryMap};

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error on {0}: {1}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),
    #[error("Could not read relocations from ELF object: {0}")]
    ReadRelaError(#[from] delf::ReadRelaError),
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("unimplemented relocation: {0:?}")]
    UnimplementedRelocation(delf::RelType),
    #[error("unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("undefined symbol: {0:?}")]
    UndefinedSymbol(NamedSym),
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,

    pub objects_by_path: HashMap<PathBuf, usize>,

    pub search_path: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            objects_by_path: HashMap::new(),
            search_path: vec!["/usr/lib/x86_64-linux-gnu/".into()],
        }
    }

    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};

        for obj in &self.objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;
                for flag in seg.flags.iter() {
                    protection |= match flag {
                        delf::SegmentFlag::Read => Protection::READ,
                        delf::SegmentFlag::Write => Protection::WRITE,
                        delf::SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }
                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }
        Ok(())
    }

    pub fn lookup_symbol(&self, wanted: &ObjectSym, ignore_self: bool) -> ResolvedSym {
        for obj in &self.objects {
            if ignore_self && std::ptr::eq(wanted.obj, obj) {
                continue;
            }

            if let Some(syms) = obj.sym_map.get_vec(&wanted.sym.name) {
                if let Some(sym) = syms.iter().find(|sym| !sym.sym.shndx.is_undef()) {
                    return ResolvedSym::Defined(ObjectSym { obj, sym });
                }
            }
        }
        ResolvedSym::Undefined
    }

    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        let rels: Vec<_> = self
            .objects
            .iter()
            .rev()
            .flat_map(|obj| obj.rels.iter().map(move |rel| ObjectRel { obj, rel }))
            .collect();

        for rel in rels {
            self.apply_relocation(rel)?;
        }
        Ok(())
    }

    fn apply_relocation(&self, objrel: ObjectRel) -> Result<(), RelocationError> {
        use delf::RelType as RT;

        // destructure a bit, for convenience
        let ObjectRel { obj, rel } = objrel;
        let reltype = rel.r#type;
        let addend = rel.addend;

        // this is the symbol we're looking for.
        // note that it may be symbol 0, which has an empty name - that's fine.
        let wanted = ObjectSym {
            obj,
            sym: &obj.syms[rel.sym as usize],
        };

        // when doing a lookup, only ignore the relocation's object if
        // we're performing a Copy relocation.
        let ignore_self = matches!(reltype, RT::Copy);

        // perform symbol lookup early
        let found = match rel.sym {
            // the relocation isn't bound to any symbol, go with undef
            0 => ResolvedSym::Undefined,
            _ => match self.lookup_symbol(&wanted, ignore_self) {
                undef @ ResolvedSym::Undefined => match wanted.sym.sym.bind {
                    // undefined symbols are fine if our local symbol is weak
                    delf::SymBind::Weak => undef,
                    // otherwise, error out now
                    _ => return Err(RelocationError::UndefinedSymbol(wanted.sym.clone())),
                },
                // defined symbols are always fine
                x => x,
            },
        };

        match reltype {
            RT::_64 => unsafe {
                // we're using `set<T>()` and passing a `delf::Addr` - which is
                // just a newtype over `u64`, so everything works out!
                println!(
                    "_64: at {}, {:?} set to {}",
                    objrel.addr(),
                    *objrel.addr().as_ptr::<u64>(),
                    found.value() + addend
                );
                objrel.addr().set(found.value() + addend);
            },
            RT::Relative => unsafe {
                objrel.addr().set(obj.base + addend);
            },
            RT::IRelative => unsafe {
                type Selector = unsafe extern "C" fn() -> delf::Addr;
                let selector: Selector = std::mem::transmute(obj.base + addend);
                objrel.addr().set(selector());
            },
            RT::Copy => unsafe {
                // write() takes a &[u8], so `as_slice`'s type is inferred correctly.
                println!(
                    "Copy: {} written to {:?} from {}",
                    objrel.addr(),
                    String::from_utf8_lossy(found.value().as_slice::<u8>(found.size())),
                    found.value()
                );
                objrel.addr().write(found.value().as_slice(found.size()));
            },
            _ => return Err(RelocationError::UnimplementedRelocation(reltype)),
        }
        Ok(())
    }

    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;

        let mut a = vec![index];
        while !a.is_empty() {
            use delf::DynamicTag::Needed;
            a = a
                .into_iter()
                .map(|index| &self.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(Needed))
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
        }

        Ok(index)
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;

        use std::io::Read;
        let mut fs_file = std::fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        let mut input = Vec::new();
        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:?}", path);

        let file = delf::File::parse_or_print_error(input)
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;
        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .map(|path| String::from_utf8_lossy(path))
                .map(|path| path.replace("$ORIGIN", origin))
                .inspect(|path| println!("Found RPATH entry {:?}", path))
                .map(PathBuf::from),
        );

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|ph| ph.r#type == delf::SegmentType::Load)
        };

        let mem_range = load_segments()
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(
            mem_size,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        use std::os::unix::io::AsRawFd;
        let segments = load_segments()
            .filter(|ph| ph.memsz.0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let filesz = ph.filesz + padding;
                let map = MemoryMap::new(
                    filesz.into(),
                    &[
                        MapOption::MapReadable,
                        MapOption::MapWritable,
                        MapOption::MapExecutable,
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(offset.into()),
                        MapOption::MapAddr((base + vaddr).as_ptr()),
                    ],
                )?;
                if ph.memsz > ph.filesz {
                    // ...then we zero them!
                    // note: this works because we already reserved the *convex hull*
                    // of all segments in memory in our initial `MemoryMap::new` call,
                    // so that memory is there.
                    let mut zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;
                    unsafe {
                        // this will probably get optimized to something good.
                        for i in zero_start.as_mut_slice::<u8>(zero_len.into()) {
                            *i = 0;
                        }
                    }
                }
                // this new - we store a Vec<Segment> now, and Segment structs
                // contain the padding we used, and the flags (for later mprotect-ing)
                Ok(Segment {
                    map: Arc::new(map),
                    vaddr_range: vaddr..(ph.vaddr + ph.memsz),
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_dynsym_entries()?;
        let syms: Vec<_> = if syms.is_empty() {
            vec![]
        } else {
            let dynstr = file
                .get_dynamic_entry(delf::DynamicTag::StrTab)
                .unwrap_or_else(|_| panic!("String table not found in {:?}", path));
            let segment = segments
                .iter()
                // and here's where `vaddr_range` comes in handy
                .find(|seg| seg.vaddr_range.contains(&dynstr))
                .unwrap_or_else(|| panic!("Segment not found for string table in {:#?}", path));

            syms.into_iter()
                .map(|sym| unsafe {
                    let name = Name::mapped(
                        &segment.map,
                        // a little bit of maths can't hurt
                        (dynstr + sym.name - segment.vaddr_range.start).into(),
                    );
                    NamedSym { sym, name }
                })
                .collect()
        };

        let mut sym_map = MultiMap::new();
        for sym in &syms {
            sym_map.insert(sym.name.clone(), sym.clone())
        }

        let mut rels = Vec::new();
        rels.extend(file.read_rela_entries()?);
        rels.extend(file.read_jmp_rel_entries()?);

        let object = Object {
            path: path.clone(),
            base,
            segments,
            mem_range,
            file,
            syms,
            sym_map,
            rels,
        };

        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr: *const u8 = (base + delf::Addr(0x2000)).as_ptr();
            dbg!(msg_addr);
            let msg_slice = unsafe { std::slice::from_raw_parts(msg_addr, 0x26) };
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }

        let index = self.objects.len();
        self.objects.push(object);
        self.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }
}

use custom_debug_derive::Debug as CustomDebug;
use enumflags2::BitFlags;
use multimap::MultiMap;

#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: Arc<MemoryMap>,
    pub vaddr_range: Range<delf::Addr>,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

#[derive(Clone, Debug)]
pub struct NamedSym {
    sym: delf::Sym,
    name: Name,
}

#[derive(Debug, Clone)]
struct ObjectSym<'a> {
    obj: &'a Object,
    sym: &'a NamedSym,
}

impl ObjectSym<'_> {
    fn value(&self) -> delf::Addr {
        self.obj.base + self.sym.sym.value
    }
}

#[derive(Debug, Clone)]
enum ResolvedSym<'a> {
    Defined(ObjectSym<'a>),
    Undefined,
}

impl ResolvedSym<'_> {
    fn value(&self) -> delf::Addr {
        match self {
            Self::Defined(sym) => sym.value(),
            Self::Undefined => delf::Addr(0x0),
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Defined(sym) => sym.sym.sym.size as usize,
            Self::Undefined => 0,
        }
    }
}

#[derive(Debug)]
struct ObjectRel<'a> {
    obj: &'a Object,
    rel: &'a delf::Rela,
}

impl ObjectRel<'_> {
    fn addr(&self) -> delf::Addr {
        self.obj.base + self.rel.offset
    }
}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,

    pub base: delf::Addr,

    // we're skipping this one because it would get *real* verbose
    #[debug(skip)]
    pub file: delf::File<Vec<u8>>,

    pub mem_range: Range<delf::Addr>,

    pub segments: Vec<Segment>,

    #[debug(skip)]
    pub syms: Vec<NamedSym>,

    #[debug(skip)]
    pub sym_map: MultiMap<Name, NamedSym>,

    #[debug(skip)]
    pub rels: Vec<delf::Rela>,
}

use std::{
    cmp::{max, min},
    ops::Range,
};

use crate::name::Name;

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

fn dump_maps(msg: &str) {
    use std::{fs, process};

    println!("======== MEMORY MAPS: {}", msg);
    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{}", line));
    println!("=============================");
}
