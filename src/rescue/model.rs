//! What a search finds, and how file types are grouped.

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Method {
    /// Found in a file system's records, with its original name and folder.
    Undelete,
    /// Found by recognising its content (the name is lost).
    Carved,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Chance {
    Good,
    Fair,
    Poor,
    Unknown,
}

impl Chance {
    pub fn label(self) -> &'static str {
        match self {
            Chance::Good => "Good",
            Chance::Fair => "Fair",
            Chance::Poor => "Poor",
            Chance::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Found {
    pub name: String,
    /// Folder inside the volume, like "/Photos/2024" (empty for content finds).
    pub folder: String,
    pub ext: String,
    pub size: u64,
    pub method: Method,
    /// File system it came from ("FAT32", "NTFS", ...) or the volume for content finds.
    pub fs: String,
    /// Which volume (partition) it was found on.
    pub volume: String,
    /// Where its bytes are on the disk: (absolute offset, length).
    pub extents: Vec<(u64, u64)>,
    /// Small NTFS files keep their bytes inside the file record.
    pub inline_data: Option<Vec<u8>>,
    pub chance: Chance,
    pub note: String,
}

impl Found {
    pub fn offset(&self) -> u64 {
        self.extents.first().map(|e| e.0).unwrap_or(0)
    }
    pub fn category(&self) -> Category {
        category_of(&self.ext)
    }
    pub fn full_path(&self) -> String {
        if self.folder.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.folder.trim_end_matches('/'), self.name)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Category {
    Pictures,
    Videos,
    Music,
    Documents,
    Archives,
    Programs,
    Databases,
    Other,
}

pub const CATEGORIES: [Category; 8] = [
    Category::Pictures,
    Category::Videos,
    Category::Music,
    Category::Documents,
    Category::Archives,
    Category::Programs,
    Category::Databases,
    Category::Other,
];

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Pictures => "Pictures",
            Category::Videos => "Videos",
            Category::Music => "Music & sound",
            Category::Documents => "Documents",
            Category::Archives => "Archives",
            Category::Programs => "Programs",
            Category::Databases => "Databases",
            Category::Other => "Other files",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            Category::Pictures => "🖼",
            Category::Videos => "🎞",
            Category::Music => "🎵",
            Category::Documents => "📄",
            Category::Archives => "📦",
            Category::Programs => "⚙",
            Category::Databases => "🗄",
            Category::Other => "📁",
        }
    }
    pub fn color(self) -> [u8; 3] {
        match self {
            Category::Pictures => [236, 120, 90],
            Category::Videos => [200, 110, 220],
            Category::Music => [90, 190, 230],
            Category::Documents => [110, 160, 245],
            Category::Archives => [230, 190, 80],
            Category::Programs => [150, 200, 120],
            Category::Databases => [120, 210, 190],
            Category::Other => [160, 160, 170],
        }
    }
}

pub fn category_of(ext: &str) -> Category {
    match ext {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tif" | "tiff" | "webp" | "heic" | "heif" | "psd" | "ico"
        | "cr2" | "nef" | "arw" | "dng" | "raw" | "svg" => Category::Pictures,
        "mp4" | "mov" | "avi" | "mkv" | "webm" | "3gp" | "flv" | "wmv" | "mpg" | "mpeg" | "m4v" => Category::Videos,
        "mp3" | "wav" | "ogg" | "flac" | "m4a" | "opus" | "wma" | "aac" | "mid" | "midi" => Category::Music,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" | "rtf" | "txt" | "epub"
        | "csv" | "md" | "html" | "htm" | "xml" | "json" | "ole" => Category::Documents,
        "zip" | "rar" | "7z" | "gz" | "tar" | "jar" | "apk" | "xz" | "bz2" | "cab" | "iso" => Category::Archives,
        "exe" | "dll" | "msi" | "elf" | "sys" | "so" | "app" | "bat" | "sh" => Category::Programs,
        "sqlite" | "db" | "sqlite3" | "mdb" | "accdb" => Category::Databases,
        _ => Category::Other,
    }
}

pub fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() && e.len() <= 8 => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Does the start of the content look like what the extension promises?
/// None when we don't know what that kind of file starts with.
pub fn content_matches(ext: &str, head: &[u8]) -> Option<bool> {
    let starts = |sig: &[u8]| head.len() >= sig.len() && &head[..sig.len()] == sig;
    let r = match ext {
        "jpg" | "jpeg" => starts(&[0xFF, 0xD8, 0xFF]),
        "png" => starts(b"\x89PNG"),
        "gif" => starts(b"GIF8"),
        "bmp" => starts(b"BM"),
        "pdf" => starts(b"%PDF"),
        "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "jar" | "apk" | "epub" => starts(b"PK"),
        "rar" => starts(b"Rar!"),
        "7z" => starts(b"7z\xBC\xAF"),
        "gz" => starts(&[0x1F, 0x8B]),
        "wav" | "avi" | "webp" => starts(b"RIFF"),
        "mp4" | "mov" | "m4a" | "3gp" | "heic" | "m4v" => head.len() >= 8 && &head[4..8] == b"ftyp",
        "mkv" | "webm" => starts(&[0x1A, 0x45, 0xDF, 0xA3]),
        "ogg" | "opus" => starts(b"OggS"),
        "flac" => starts(b"fLaC"),
        "mp3" => starts(b"ID3") || (head.len() >= 2 && head[0] == 0xFF && head[1] & 0xE0 == 0xE0),
        "exe" | "dll" | "sys" => starts(b"MZ"),
        "doc" | "xls" | "ppt" | "msi" => starts(&[0xD0, 0xCF, 0x11, 0xE0]),
        "sqlite" | "sqlite3" => starts(b"SQLite format 3"),
        "tif" | "tiff" => starts(b"II*\0") || starts(b"MM\0*"),
        "txt" | "csv" | "md" | "json" | "xml" | "html" | "htm" => {
            // The end of the last cluster is usually zeros; only judge the text itself.
            let trimmed = &head[..head.iter().rposition(|&b| b != 0).map(|p| p + 1).unwrap_or(0)];
            if trimmed.is_empty() {
                // Nothing but zeros: whatever was there is gone.
                return if head.is_empty() { None } else { Some(false) };
            }
            let head = trimmed;
            let n = head.len().min(256);
            head[..n].iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || b >= 0x20)
        }
        _ => return None,
    };
    Some(r)
}

/// A partition or file system found on the disk.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Volume {
    pub label: String,
    pub start: u64,
    pub len: u64,
    pub fs: FsKind,
    pub kind: String,
    /// Found by the deep search rather than in the partition table.
    pub lost: bool,
    /// Where its boot sector is read from (a backup copy when the first one is gone).
    pub boot: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum FsKind {
    Fat,
    ExFat,
    Ntfs,
    Ext,
    HfsPlus,
    Apfs,
    Unknown,
}

impl FsKind {
    pub fn label(self) -> &'static str {
        match self {
            FsKind::Fat => "FAT",
            FsKind::ExFat => "exFAT",
            FsKind::Ntfs => "NTFS",
            FsKind::Ext => "ext2/3/4",
            FsKind::HfsPlus => "HFS+",
            FsKind::Apfs => "APFS",
            FsKind::Unknown => "unknown",
        }
    }
    pub fn can_undelete(self) -> bool {
        matches!(self, FsKind::Fat | FsKind::ExFat | FsKind::Ntfs)
    }
}

/// Turn a recovered name into one that's safe on this computer.
pub fn safe_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_control() || "<>:\"/\\|?*".contains(c) { '_' } else { c })
        .collect();
    s = s.trim_matches(|c: char| c == ' ' || c == '.').to_string();
    if s.is_empty() {
        s = "unnamed".into();
    }
    s
}
