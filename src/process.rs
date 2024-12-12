use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use mmap::MemoryMap;

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
        let input = fs::read(&path).map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:?}", path);
        let file = delf::File::parse_or_print_error(&input[..])
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;
        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .map(|path| path.replace("$ORIGIN", origin))
                .inspect(|path| println!("Found RPATH entry {:?}", path))
                .map(PathBuf::from),
        );

        let object = Object {
            path: path.clone(),
            base: delf::Addr(0x400000),
            maps: Vec::new(),
            file,
        };

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

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,

    pub base: delf::Addr,

    // we're skipping this one because it would get *real* verbose
    #[debug(skip)]
    pub file: delf::File,

    // `MemoryMap` does not implement `Debug`, so we need to skip it.
    // if we weren't using `custom_debug_derive`, we would have to do an
    // entirely custom `fmt::Debug` implementation for `Object`!
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
}
