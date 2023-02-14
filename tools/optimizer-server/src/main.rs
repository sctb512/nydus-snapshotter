use fanotify::low_level::*;
use nix::poll::{poll, PollFd, PollFlags};
use nix::sched::{setns, CloneFlags};
use nix::unistd::fork;
use nix::unistd::ForkResult::{Child, Parent};
use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;

const DEFAULT_TARGET: &str = "/";

#[derive(Debug)]
pub enum SetnsError {
    IO(io::Error),
    Nix(nix::Error),
}

fn get_pid() -> Option<String> {
    match env::var("_MNTNS_PID") {
        Ok(string) => Some(string),
        Err(_) => None,
    }
}

fn get_target() -> String {
    match env::var("_TARGET") {
        Ok(string) => string,
        Err(_) => DEFAULT_TARGET.to_string(),
    }
}

fn get_fd_path(fd: i32) -> Option<String> {
    let fd_path = format!("/proc/self/fd/{}", fd);
    if let Ok(path) = fs::read_link(fd_path) {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn set_ns(ns_path: String, flags: CloneFlags) -> Result<(), SetnsError> {
    fs::File::open(Path::new(ns_path.as_str()))
        .map(|file| {
            setns(file.as_raw_fd(), flags)
                .map_err(|e| SetnsError::Nix(e))
                .unwrap()
        })
        .map_err(|e| SetnsError::IO(e))
}

fn init_fanotify() -> Result<i32, io::Error> {
    fanotify_init(
        FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE,
    )
}

fn mark_fanotify(fd: i32, path: &str) -> Result<(), io::Error> {
    fanotify_mark(
        fd,
        FAN_MARK_ADD | FAN_MARK_MOUNT,
        FAN_OPEN | FAN_CLOSE_WRITE,
        AT_FDCWD,
        path,
    )
}

fn send_path(writer: &mut io::Stdout, path: String) -> Result<(), io::Error> {
    writer.write_all(path.as_bytes())?;
    writer.flush()
}

fn handle_fanotify_event(fd: i32) {
    let mut writer = io::stdout();

    let mut fds = [PollFd::new(fd.as_raw_fd(), PollFlags::POLLIN)];
    loop {
        let poll_num = poll(&mut fds, -1).unwrap();
        if poll_num > 0 {
            if let Some(flag) = fds[0].revents() {
                if flag.contains(PollFlags::POLLIN) {
                    let events = fanotify_read(fd);
                    for event in events {
                        if let Some(path) = get_fd_path(event.fd) {
                            if let Err(e) = send_path(&mut writer, path.clone() + "\n") {
                                eprintln!("send path {} failed: {:?}", path, e);
                            };
                            close_fd(event.fd);
                        }
                    }
                }
            }
        } else {
            eprintln!("poll_num <= 0!");
            break;
        }
    }
}

fn main() {
    if let Some(pid) = get_pid() {
        if let Err(e) = set_ns(format!("/proc/{}/ns/pid", pid), CloneFlags::CLONE_NEWPID)
            .map(|_| set_ns(format!("/proc/{}/ns/mnt", pid), CloneFlags::CLONE_NEWNS))
        {
            eprintln!("join namespace failed {:?}", e);
            return;
        }
    }

    let pid = unsafe { fork() };
    match pid.expect("fork failed: unable to create child process") {
        Child => {
            if let Err(e) = init_fanotify().map(|fd| {
                mark_fanotify(fd, get_target().as_str()).map(|_| handle_fanotify_event(fd))
            }) {
                eprintln!("failed to start fanotify server {:?}", e);
                return;
            }
        }
        Parent { child: _ } => return,
    }
}
