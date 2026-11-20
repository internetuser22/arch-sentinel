//! File Rescue engine (from the person's own "File Rescue" project): reads disks
//! read-only, finds deleted files by name (FAT, exFAT, NTFS) and by content, finds
//! previous partitions, and can zero-fill deleted files in place - only where every
//! piece lies in space the file system marks as free.
#![allow(dead_code)]

pub mod carve;
pub mod disk;
pub mod elevate;
pub mod fat;
pub mod model;
pub mod ntfs;
pub mod partfind;
pub mod parts;
pub mod sample;
pub mod scan;
pub mod wipe;
pub mod helper;
