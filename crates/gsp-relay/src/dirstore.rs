//! Durable store: one append-only log file per fragment.
//!
//! ```text
//! <data_dir>/fragments/<hex fragment id>.log
//!
//! file   = header record*
//! header = "GSPRLY01" id_len:u8 fragment_id token_hash:32 blake3(all before):32
//! record = len:u32le blake3(item):32 item
//! ```
//!
//! The n-th record of a file is cursor n. Nothing is ever rewritten or
//! deleted, so cursors are stable across restarts.
//!
//! **Fsync policy.** A new fragment file is written to a temporary name,
//! synced, renamed into place, and the directory is synced: a fragment's
//! token hash is durable before its first item is acknowledged, under either
//! policy. Item writes follow [`Fsync`]: with `Always` (the default) one
//! `fdatasync` per push happens before the `Ack`; with `Never` nothing is
//! synced and a crash can lose acknowledged items.
//!
//! **Recovery.** On startup each file is replayed. The first record that is
//! incomplete or fails its checksum, and everything after it, is cut off
//! (a torn tail from a crash mid-write). With `Fsync::Always` such a record
//! was never acknowledged. The same rule is applied to damage in the middle
//! of a file, which loses the records after the damaged one; the number of
//! bytes dropped is logged.
//!
//! One relay process per directory: there is no lock file.

use crate::config::Fsync;
use crate::log::{frag, warning};
use crate::store::{LoadedFragment, Store, TokenHash, lock};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"GSPRLY01";
const RECORD_HEADER: usize = 4 + 32;

/// Hard upper bound on one record, independent of configuration. Replay
/// never allocates more than this for a length field read from disk.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

struct FragFile {
    file: File,
    header_len: u64,
    /// End offset of each record; record `i` is cursor `i + 1`.
    ends: Vec<u64>,
    /// Set when a failed append could not be rolled back.
    broken: bool,
}

impl FragFile {
    fn end(&self) -> u64 {
        self.ends.last().copied().unwrap_or(self.header_len)
    }
    fn start_of(&self, index: usize) -> u64 {
        if index == 0 {
            self.header_len
        } else {
            self.ends[index - 1]
        }
    }
}

/// Directory-backed [`Store`]. See the module docs for format and guarantees.
pub struct DirStore {
    dir: PathBuf,
    fsync: Fsync,
    fragments: Mutex<HashMap<Vec<u8>, Arc<Mutex<FragFile>>>>,
}

fn hex(id: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(id.len() * 2);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn bad(path: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {what}", path.display()),
    )
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn header_bytes(fragment_id: &[u8], token_hash: &TokenHash) -> io::Result<Vec<u8>> {
    let id_len = u8::try_from(fragment_id.len())
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fragment id length"))?;
    let mut h = Vec::with_capacity(MAGIC.len() + 1 + fragment_id.len() + 64);
    h.extend_from_slice(MAGIC);
    h.push(id_len);
    h.extend_from_slice(fragment_id);
    h.extend_from_slice(token_hash);
    let sum = blake3::hash(&h);
    h.extend_from_slice(sum.as_bytes());
    Ok(h)
}

impl DirStore {
    /// Use `data_dir` (created if missing). Files are read by
    /// [`Store::load`], which the relay calls once at startup.
    pub fn open(data_dir: impl Into<PathBuf>, fsync: Fsync) -> io::Result<DirStore> {
        let dir = data_dir.into().join("fragments");
        fs::create_dir_all(&dir)?;
        Ok(DirStore {
            dir,
            fsync,
            fragments: Mutex::new(HashMap::new()),
        })
    }

    fn path(&self, fragment_id: &[u8]) -> PathBuf {
        self.dir.join(format!("{}.log", hex(fragment_id)))
    }

    fn get(&self, fragment_id: &[u8]) -> io::Result<Arc<Mutex<FragFile>>> {
        lock(&self.fragments)
            .get(fragment_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown fragment"))
    }

    /// Replay one log file, cutting off a torn tail.
    fn replay(&self, path: &Path) -> io::Result<(LoadedFragment, FragFile)> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let file_len = file.metadata()?.len();
        let mut r = BufReader::new(&file);

        let mut fixed = [0u8; 9];
        r.read_exact(&mut fixed)
            .map_err(|_| bad(path, "short header"))?;
        if &fixed[..8] != MAGIC {
            return Err(bad(path, "not a gsp-relay fragment log"));
        }
        let id_len = usize::from(fixed[8]);
        let mut rest = vec![0u8; id_len + 64];
        r.read_exact(&mut rest)
            .map_err(|_| bad(path, "short header"))?;
        let (id, tail) = rest.split_at(id_len);
        let (token, sum) = tail.split_at(32);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&fixed).update(id).update(token);
        if hasher.finalize().as_bytes() != sum || id_len == 0 {
            return Err(bad(path, "header checksum mismatch"));
        }
        if path.file_name().and_then(|n| n.to_str()) != Some(&format!("{}.log", hex(id))) {
            return Err(bad(path, "file name does not match the fragment id inside"));
        }
        let header_len = (9 + id_len + 64) as u64;
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(token);

        let mut items = Vec::new();
        let mut ends = Vec::new();
        let mut pos = header_len;
        let mut buf = Vec::new();
        loop {
            let remaining = file_len - pos;
            if remaining < RECORD_HEADER as u64 {
                break;
            }
            let mut head = [0u8; RECORD_HEADER];
            r.read_exact(&mut head)?;
            let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
            // The length field is untrusted: bound it by what is actually in
            // the file and by the hard cap before allocating.
            if u64::from(len) > remaining - RECORD_HEADER as u64 || len as usize > MAX_RECORD_BYTES
            {
                break;
            }
            buf.resize(len as usize, 0);
            r.read_exact(&mut buf)?;
            let sum = blake3::hash(&buf);
            if sum.as_bytes() != &head[4..] {
                break;
            }
            pos += RECORD_HEADER as u64 + u64::from(len);
            ends.push(pos);
            items.push((*sum.as_bytes(), len));
        }
        drop(r);
        if pos < file_len {
            warning!(
                "torn_tail",
                "fragment={} kept_items={} dropped_bytes={}",
                frag(id),
                items.len(),
                file_len - pos
            );
            file.set_len(pos)?;
            file.sync_all()?;
        }
        let loaded = LoadedFragment {
            fragment_id: id.to_vec(),
            token_hash,
            items,
        };
        let ff = FragFile {
            file,
            header_len,
            ends,
            broken: false,
        };
        Ok((loaded, ff))
    }
}

impl Store for DirStore {
    fn load(&self) -> io::Result<Vec<LoadedFragment>> {
        let mut out = Vec::new();
        let mut map = HashMap::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            match path.extension().and_then(|e| e.to_str()) {
                // Left behind by a crash while creating a fragment; it was
                // never acknowledged.
                Some("tmp") => fs::remove_file(&path)?,
                Some("log") => {
                    let (loaded, ff) = self.replay(&path)?;
                    map.insert(loaded.fragment_id.clone(), Arc::new(Mutex::new(ff)));
                    out.push(loaded);
                }
                _ => {}
            }
        }
        *lock(&self.fragments) = map;
        Ok(out)
    }

    fn create(&self, fragment_id: &[u8], token_hash: &TokenHash) -> io::Result<()> {
        let header = header_bytes(fragment_id, token_hash)?;
        let path = self.path(fragment_id);
        let tmp = path.with_extension("tmp");
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "fragment log already exists",
            ));
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&header)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &path)?;
        sync_dir(&self.dir)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::End(0))?;
        let ff = FragFile {
            file,
            header_len: header.len() as u64,
            ends: Vec::new(),
            broken: false,
        };
        lock(&self.fragments).insert(fragment_id.to_vec(), Arc::new(Mutex::new(ff)));
        Ok(())
    }

    fn append(&self, fragment_id: &[u8], first_seq: u64, items: &[Vec<u8>]) -> io::Result<()> {
        let ff = self.get(fragment_id)?;
        let mut ff = lock(&ff);
        if ff.broken {
            return Err(io::Error::other("fragment log needs a restart to recover"));
        }
        if first_seq != ff.ends.len() as u64 + 1 {
            return Err(io::Error::other("append out of sequence"));
        }
        let total: usize = items.iter().map(|i| RECORD_HEADER + i.len()).sum();
        let mut buf = Vec::with_capacity(total);
        let start = ff.end();
        let mut new_ends = Vec::with_capacity(items.len());
        for item in items {
            let len = u32::try_from(item.len())
                .ok()
                .filter(|n| *n as usize <= MAX_RECORD_BYTES)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "item too large"))?;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(blake3::hash(item).as_bytes());
            buf.extend_from_slice(item);
            new_ends.push(start + buf.len() as u64);
        }
        let fsync = self.fsync;
        let written = (|| {
            ff.file.seek(SeekFrom::Start(start))?;
            ff.file.write_all(&buf)?;
            if fsync == Fsync::Always {
                ff.file.sync_data()?;
            }
            Ok(())
        })();
        if let Err(e) = written {
            // Roll back so a later append cannot land after half a record.
            if ff.file.set_len(start).is_err() {
                ff.broken = true;
            }
            return Err(e);
        }
        ff.ends.extend(new_ends);
        Ok(())
    }

    fn read(
        &self,
        fragment_id: &[u8],
        after: u64,
        max_items: usize,
        max_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        let ff = self.get(fragment_id)?;
        let mut ff = lock(&ff);
        let first = usize::try_from(after)
            .unwrap_or(usize::MAX)
            .min(ff.ends.len());
        let mut last = first;
        let mut bytes = 0usize;
        while last < ff.ends.len() && last - first < max_items {
            let len = (ff.ends[last] - ff.start_of(last)) as usize - RECORD_HEADER;
            if last > first && bytes.saturating_add(len) > max_bytes {
                break;
            }
            bytes = bytes.saturating_add(len);
            last += 1;
        }
        if last == first {
            return Ok(Vec::new());
        }
        let span_start = ff.start_of(first);
        let span = (ff.ends[last - 1] - span_start) as usize;
        let mut buf = vec![0u8; span];
        ff.file.seek(SeekFrom::Start(span_start))?;
        ff.file.read_exact(&mut buf)?;
        let mut out = Vec::with_capacity(last - first);
        for i in first..last {
            let a = (ff.start_of(i) - span_start) as usize;
            let b = (ff.ends[i] - span_start) as usize;
            let (head, item) = buf[a..b].split_at(RECORD_HEADER);
            if blake3::hash(item).as_bytes() != &head[4..] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored record failed its checksum",
                ));
            }
            out.push(item.to_vec());
        }
        Ok(out)
    }
}
