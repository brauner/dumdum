use libc;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::thread;

const SO_PEERPIDFD: i32 = 77; // Correct value for Linux 6.7+
const SOL_SOCKET: i32 = 1;

// PIDFD_INFO_* flags
pub const PIDFD_INFO_PID: u64 = 1 << 0;
pub const PIDFD_INFO_CREDS: u64 = 1 << 1;
pub const PIDFD_INFO_CGROUPID: u64 = 1 << 2;
pub const PIDFD_INFO_EXIT: u64 = 1 << 3;
pub const PIDFD_INFO_COREDUMP: u64 = 1 << 4;

// Size of first published struct
pub const PIDFD_INFO_SIZE_VER0: u32 = 64;

// Values for @coredump_mask in pidfd_info
pub const PIDFD_COREDUMPED: u32 = 1 << 0;
pub const PIDFD_COREDUMP_SKIP: u32 = 1 << 1;
pub const PIDFD_COREDUMP_USER: u32 = 1 << 2;
pub const PIDFD_COREDUMP_ROOT: u32 = 1 << 3;

// PIDFS ioctl magic
pub const PIDFS_IOCTL_MAGIC: u8 = 0xFF;

// Add these definitions at the top of your file

// _IOC direction bits
const IOC_NRBITS: u8 = 8;
const IOC_TYPEBITS: u8 = 8;
const IOC_SIZEBITS: u8 = 14;

const IOC_NRSHIFT: u8 = 0;
const IOC_TYPESHIFT: u8 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u8 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u8 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn _ioc(dir: u32, type_: u32, nr: u32, size: u32) -> u64 {
    ((dir as u64) << IOC_DIRSHIFT)
        | ((type_ as u64) << IOC_TYPESHIFT)
        | ((nr as u64) << IOC_NRSHIFT)
        | ((size as u64) << IOC_SIZESHIFT)
}

const fn _iowr(type_: u32, nr: u32, size: u32) -> u64 {
    _ioc(IOC_READ | IOC_WRITE, type_, nr, size)
}

pub const PIDFD_GET_INFO: u64 = _iowr(
    PIDFS_IOCTL_MAGIC as u32,
    11,
    std::mem::size_of::<PidfdInfo>() as u32,
);

// FFI-compatible struct
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PidfdInfo {
    pub mask: u64,
    pub cgroupid: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub exit_code: i32,
    pub coredump_mask: u32,
    pub __spare1: u32,
}

// Coredump flags
pub const COREDUMP_KERNEL: u64 = 1 << 0;
pub const COREDUMP_USERSPACE: u64 = 1 << 1;
pub const COREDUMP_REJECT: u64 = 1 << 2;
pub const COREDUMP_WAIT: u64 = 1 << 3;

// Size of first published struct
pub const COREDUMP_ACK_SIZE_VER0: u32 = 16;

// C struct: struct coredump_req
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CoredumpReq {
    pub size: u32,
    pub size_ack: u32,
    pub mask: u64,
}

// C struct: struct coredump_ack
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CoredumpAck {
    pub size: u32,
    pub spare: u32,
    pub mask: u64,
}

// C enum: enum coredump_oob
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoredumpOob {
    InvalidSize = 1,
    Unsupported = 2,
    Conflicting = 3,
    __Max = 255,
}

impl From<u8> for CoredumpOob {
    fn from(val: u8) -> Self {
        match val {
            1 => CoredumpOob::InvalidSize,
            2 => CoredumpOob::Unsupported,
            3 => CoredumpOob::Conflicting,
            _ => CoredumpOob::__Max,
        }
    }
}

fn get_peer_pidfd(stream: &UnixStream) -> io::Result<RawFd> {
    let fd = stream.as_raw_fd();
    let mut pidfd: RawFd = -1;
    let mut pidfd_len = std::mem::size_of::<RawFd>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERPIDFD,
            &mut pidfd as *mut _ as *mut libc::c_void,
            &mut pidfd_len as *mut _,
        )
    };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pidfd)
    }
}

fn get_pidfd_info<T: AsRawFd>(pidfd: &T, mask: u64) -> io::Result<PidfdInfo> {
    let mut info = PidfdInfo {
        mask,
        cgroupid: 0,
        pid: 0,
        tgid: 0,
        ppid: 0,
        ruid: 0,
        rgid: 0,
        euid: 0,
        egid: 0,
        suid: 0,
        sgid: 0,
        fsuid: 0,
        fsgid: 0,
        exit_code: 0,
        coredump_mask: 0,
        __spare1: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            pidfd.as_raw_fd() as libc::c_int,
            PIDFD_GET_INFO,
            &mut info as *mut _,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

fn read_coredump_req(stream: &UnixStream) -> io::Result<CoredumpReq> {
    let fd = stream.as_raw_fd();

    let mut req = CoredumpReq {
        size: 0,
        size_ack: 0,
        mask: 0,
    };

    let field_size = std::mem::size_of_val(&req.size);
    /* Peek the size of the coredump request. */
    let ret = unsafe {
        libc::recv(
            fd,
            &mut req as *mut CoredumpReq as *mut libc::c_void,
            field_size,
            libc::MSG_PEEK | libc::MSG_WAITALL,
        )
    };

    if ret != field_size as isize {
        println!("Failed to peek coredump request size");
        return Err(io::Error::last_os_error());
    }
    let kernel_size = req.size as usize;

    // Now use the minimum of the user and kernel size to read the full request.
    let user_size = std::mem::size_of::<CoredumpReq>();
    let ack_size = std::cmp::min(user_size, kernel_size);
    let ret = unsafe {
        libc::recv(
            fd,
            &mut req as *mut CoredumpReq as *mut libc::c_void,
            ack_size,
            libc::MSG_WAITALL,
        )
    };
    if ret != ack_size as isize {
        return Err(io::Error::last_os_error());
    }

    if is_msg_oob_supported() {
        return Ok(req);
    }

    // Discard any extra data if kernel_size > user_size
    if kernel_size > user_size {
        let mut remaining = kernel_size - user_size;
        const BUF_SIZE: usize = 4096;
        let mut buffer = [0u8; BUF_SIZE];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, BUF_SIZE);
            let ret = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    to_read,
                    libc::MSG_WAITALL,
                )
            };
            if ret <= 0 {
                return Err(io::Error::last_os_error());
            }
            remaining -= ret as usize;
        }
    }

    Ok(req)
}

fn send_coredump_ack(
    stream: &std::os::unix::net::UnixStream,
    req: &CoredumpReq,
) -> std::io::Result<()> {
    let size = std::cmp::min(std::mem::size_of::<CoredumpAck>() as u32, req.size_ack);
    let ack = CoredumpAck {
        size,
        spare: 0,
        mask: COREDUMP_KERNEL | COREDUMP_WAIT,
    };
    let fd = stream.as_raw_fd();
    let ptr = &ack as *const CoredumpAck as *const libc::c_void;
    let ret = unsafe { libc::send(fd, ptr, size as usize, libc::MSG_NOSIGNAL) };
    if ret != size as isize {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// Retrieve the inode number (lower 32 bits) via stat
fn pidfd_inode_number<T: AsRawFd>(pidfd: &T) -> io::Result<u32> {
    let fd = pidfd.as_raw_fd();
    // SAFETY: We do not take ownership of the fd, so we must not close it.
    let file = unsafe { File::from_raw_fd(fd) };
    let ino = file.metadata()?.ino() as u32;
    std::mem::forget(file); // Prevent closing fd
    Ok(ino)
}

// Retrieve the inode generation (upper 32 bits) via FS_IOC_GETVERSION ioctl
fn pidfd_inode_generation<T: AsRawFd>(pidfd: &T) -> io::Result<u32> {
    let fd = pidfd.as_raw_fd();
    let mut version: u32 = 0;
    let ret = unsafe { libc::ioctl(fd, libc::FS_IOC_GETVERSION, &mut version as *mut u32) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(version)
    }
}

// Combine both into a 64-bit inode identifier
fn pidfd_inode_unique<T: AsRawFd>(pidfd: &T) -> io::Result<u64> {
    let ino = pidfd_inode_number(pidfd)? as u64;
    let gen = pidfd_inode_generation(pidfd)? as u64;
    Ok((gen << 32) | ino)
}

fn get_cmd_basename(pid: u32) -> io::Result<String> {
    let mut cmdline = String::new();
    std::fs::File::open(format!("/proc/{}/cmdline", pid))?.read_to_string(&mut cmdline)?;
    let first_arg = cmdline.split('\0').next().unwrap_or("");
    let basename = Path::new(first_arg)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    Ok(basename)
}

fn open_coredump_file<T: AsRawFd>(pidfd: &T, pid: u32) -> io::Result<File> {
    let inode = pidfd_inode_unique(pidfd)?;
    let basename = get_cmd_basename(pid)?;
    let filename = format!("dumdum.{}.{}.core", basename, inode);
    println!("Opening coredump file: {}", filename);
    let path = PathBuf::from("/var/lib/dumdum/").join(filename);
    // Create the file for writing (fail if it already exists)
    File::create(path)
}

static MSG_OOB_SUPPORTED: OnceLock<bool> = OnceLock::new();

fn is_msg_oob_supported() -> bool {
    *MSG_OOB_SUPPORTED.get_or_init(|| {
        let (fd0, _fd1) = unsafe {
            let mut sv = [0; 2];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) < 0 {
                return false;
            }
            (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1]))
        };

        let c: u8 = b'X';
        let ret = unsafe {
            libc::send(
                fd0.as_raw_fd(),
                &c as *const u8 as *const _,
                1,
                libc::MSG_OOB,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EINVAL || err == libc::EOPNOTSUPP {
                return false;
            }
            return false;
        }
        true
    })
}

fn shovel_coredump(
    stream: &mut std::os::unix::net::UnixStream,
    file: &mut std::fs::File,
) -> std::io::Result<u64> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to get page size",
        ));
    }
    let page_size = page_size as usize;
    let mut buf = vec![0u8; page_size];
    let mut total = 0u64;

    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        total += n as u64;
    }

    Ok(total)
}

fn create_dir_fd_based(parent: &str, child: &str) -> io::Result<()> {
    let parent_fd = File::open(parent)?;
    let ret = unsafe {
        libc::mkdirat(
            parent_fd.as_raw_fd(),
            format!("{}\0", child).as_ptr() as *const i8,
            0o755,
        )
    };
    if ret < 0 && std::io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        return Err(std::io::Error::last_os_error());
    }
    let child_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            format!("{}\0", child).as_ptr() as *const i8,
            libc::O_DIRECTORY | libc::O_RDONLY,
        )
    };
    if child_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        libc::fchown(child_fd, 0, 0);
    }
    unsafe {
        libc::close(child_fd);
    }
    Ok(())
}

fn create_dumdum_dirs() -> io::Result<()> {
    create_dir_fd_based("/var/lib", "dumdum")?;
    create_dir_fd_based("/run", "dumdum")?;
    Ok(())
}

const WORKER_COUNT: usize = 10;

fn handle_connection(mut stream: UnixStream) -> std::io::Result<()> {
    let pidfd = match get_peer_pidfd(&stream) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            eprintln!("Failed to get peer pidfd: {}", e);
            return Ok(());
        }
    };

    let pidfd_info = match get_pidfd_info(&pidfd, PIDFD_INFO_EXIT | PIDFD_INFO_COREDUMP) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Failed to get pidfd info: {}", e);
            return Ok(());
        }
    };

    if (pidfd_info.mask & PIDFD_INFO_COREDUMP) == 0 {
        eprintln!("Missing coredump information.");
        return Ok(());
    }

    if (pidfd_info.coredump_mask & PIDFD_COREDUMPED) == 0 {
        eprintln!("Unexpected connection from non-coredumping process.");
        return Ok(());
    }

    let coredump_req = match read_coredump_req(&stream) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Failed to read coredump request from the kernel: {}", e);
            return Ok(());
        }
    };

    if coredump_req.size_ack < COREDUMP_ACK_SIZE_VER0 {
        eprintln!(
            "Coredump request size is too small: {}",
            coredump_req.size_ack
        );
        std::process::exit(1);
    }

    if coredump_req.mask & (COREDUMP_KERNEL | COREDUMP_WAIT) != (COREDUMP_KERNEL | COREDUMP_WAIT) {
        eprintln!("Coredump request does not contain expected flags.");
        std::process::exit(1);
    }

    let mut core_file = match open_coredump_file(&pidfd, pidfd_info.pid) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open coredump file: {}", e);
            return Ok(());
        }
    };

    send_coredump_ack(&stream, &coredump_req)?;

    if let Err(e) = shovel_coredump(&mut stream, &mut core_file) {
        eprintln!("Failed to write coredump: {}", e);
        return Ok(());
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    let socket_path = "/run/dumdum/coredump.socket";
    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }
    create_dumdum_dirs()?;
    let listener = UnixListener::bind(socket_path)?;
    std::fs::write(
        "/proc/sys/kernel/core_pattern",
        "@@/run/dumdum/coredump.socket",
    )?;

    println!("Listening on {}", socket_path);

    let listener = Arc::new(listener);

    for _ in 0..WORKER_COUNT {
        let listener = Arc::clone(&listener);
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let _ = handle_connection(stream);
                    }
                    Err(e) => eprintln!("Connection failed: {}", e),
                }
            }
        });
    }

    loop {
        std::thread::park();
    }
}
