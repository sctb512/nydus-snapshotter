/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package conn

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/containerd/containerd/log"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

import "C"

const sourceCode string = `
#include <net/sock.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/string.h>

#define CONTAINER_ID_LEN 128
#define FILE_PATH_LEN 256
#define CMPMAX  16
#define DENTRY_DEPTH_MAX 16

struct request_info {
    char comm[16];
    char path[FILE_PATH_LEN];
    u64 position;
    u32 length;
};

struct buf_s {
    char buf[FILE_PATH_LEN*2];
};

struct buf_i {
    char buf[CONTAINER_ID_LEN];
 };

BPF_ARRAY(id_buf, struct buf_i, 1);
BPF_PERCPU_ARRAY(path_buf, struct buf_s, 1);
BPF_PERCPU_ARRAY(event_buf, struct request_info, 1);
BPF_HASH(vfs_read_start_trace, u64, struct request_info);
BPF_PERF_OUTPUT(fille_access_events);

static int container_id_filter();
static void fill_file_path(struct file *file, char *file_path);
static int local_strcmp(const char *cs, const char *ct);
static int file_filter(struct file *file);
static int trace_read_entry(struct pt_regs *ctx, struct file *file, loff_t *pos);

static int container_id_filter() {
    struct task_struct *curr_task;
    struct kernfs_node *knode, *pknode;
    char container_id[CONTAINER_ID_LEN];
    char end = 0;
    uint32_t zero = 0;
    struct buf_i *id = id_buf.lookup(&zero);
    if (!id) {
        return -1;
    }

    bpf_printk("[abin] container id: %s", id->buf);

    curr_task = (struct task_struct *) bpf_get_current_task();

    knode = curr_task->cgroups->subsys[0]->cgroup->kn;
    pknode = knode->parent;
    if(pknode != NULL)
        bpf_probe_read_str(container_id, CONTAINER_ID_LEN, knode->name);
    else
        bpf_probe_read(container_id, 1, &end);

    return local_strcmp(container_id, id->buf);
}

static void fill_file_path(struct file *file, char *file_path) {
    struct dentry *de , *de_last, *mnt_root;
    unsigned int de_depth, len, buf_pos;
    int first_de = 1;
    char slash = '/';
    int zero = 0;
    struct buf_s *buf = path_buf.lookup(&zero);

    if (!buf)
        return;

    mnt_root = file->f_path.mnt->mnt_root;
    de = file->f_path.dentry;
    de_last = NULL;
    buf_pos = FILE_PATH_LEN - 1;

    for (de_depth = 0; de_depth < DENTRY_DEPTH_MAX; de_depth++) {
        //found root dentry
        if (de == de_last || de == mnt_root) {
            //fill slash
            if (buf_pos == 0)
                break;
            buf_pos -= 1;
            bpf_probe_read(&buf->buf[buf_pos & (FILE_PATH_LEN -1)], 1, &slash);
            break;
        }

        //fill dentry name
        len = (de->d_name.len + 1) & (FILE_PATH_LEN - 1);
        if (buf_pos <= len)
            break;

        buf_pos -= len;
        if (len != bpf_probe_read_str(&buf->buf[buf_pos & (FILE_PATH_LEN -1)], len, de->d_name.name))
            break;

        //remove null with slash
        if (first_de)
            first_de = 0;
        else
            bpf_probe_read(&buf->buf[(buf_pos + len -1) & (FILE_PATH_LEN -1)], 1, &slash);

        de_last = de;
        de = de->d_parent;
    }

    bpf_probe_read_str(file_path, FILE_PATH_LEN, &buf->buf[buf_pos]);
}

/* local strcmp function, max length 16 to protect instruction loops */
static int local_strcmp(const char *cs, const char *ct)
{
    int len = 0;
    unsigned char c1, c2;

    while (len++ < CMPMAX) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
    }
    return 0;
}

// only trace common file
static int file_filter(struct file *file)
{
    int mode = file->f_inode->i_mode;
    struct super_block *mnt_sb = file->f_path.mnt->mnt_sb;
    char ovl_name[CMPMAX] = "overlay";
    char fs_type[CMPMAX] = "";

    if (!mnt_sb)
        return -1;

    if (!S_ISREG(mode))
        return -1;

    bpf_probe_read_str(fs_type, sizeof(fs_type), mnt_sb->s_type->name);
    if (local_strcmp(fs_type, ovl_name))
        return -1;

    return 0;
}

static int trace_read_entry(struct pt_regs *ctx, struct file *file, loff_t *pos)
{
    int zero = 0;
    u64 pid = bpf_get_current_pid_tgid();
    struct request_info *event = event_buf.lookup(&zero);

    if (!event)
        return 0;

    if (file_filter(file)) {
        return 0;
    }

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (container_id_filter()) {
        return 0;
    };

    bpf_probe_read(&event->position, sizeof(event->position), pos);
    fill_file_path(file, event->path);
    vfs_read_start_trace.update(&pid, event);

    return 0;
}

// vfs_read will not nested , this is safe
int trace_read_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();
    struct request_info *event = vfs_read_start_trace.lookup(&pid);
    if (!event)
        return 0;
    if (ret <= 0)
        return 0;

    event->length = ret;
    fille_access_events.perf_submit(ctx, event, sizeof(struct request_info));

    return 0;
}

int trace_vfs_read_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    return trace_read_entry(ctx, file, pos);
}

int trace_splice_read_entry(struct pt_regs *ctx, struct file *in, loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags)
{
    return trace_read_entry(ctx, in, ppos);
}

int trace_vfs_readv_entry(struct pt_regs *ctx, struct file *file, const struct iovec __user *vec,
		  unsigned long vlen, loff_t *pos, rwf_t flags)
{
    return trace_read_entry(ctx, file, pos);
}

//readahead may influence the page fault collection data, disable readahead for tracing mmap read.
int trace_page_fault(struct pt_regs *ctx, struct vm_fault *vmf)
{
    int zero = 0;
    u64 page_size = 4096;
    u64 pid = bpf_get_current_pid_tgid();
    struct request_info *event = event_buf.lookup(&zero);
    struct vm_area_struct *vma = vmf->vma;
    struct file *file = vma->vm_file;
    int container_id_len;

    if (!vma)
        return 0;

    // only trace file backed page fault
    if (!file)
        return 0;

    if (!event)
        return 0;

    if (file_filter(file)) {
        return 0;
    }

    //skip page fault for write
    if ((vmf->flags & FAULT_FLAG_WRITE) && (vma->vm_flags & VM_SHARED))
        return 0;

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    if (container_id_filter()) {
        return 0;
    };

    fill_file_path(file, event->path);
    event->position = (vma->vm_pgoff + vmf->pgoff) * page_size;
    event->length = page_size;
    fille_access_events.perf_submit(ctx, event, sizeof(struct request_info));

    return 0;
}
`

func kprobeSyscall(m *bpf.Module, syscall string, kprobeEntry string) error {
	vfsReadKprobe, err := m.LoadKprobe(kprobeEntry)
	if err != nil {
		return errors.Wrapf(err, "load entry %s", kprobeEntry)
	}

	err = m.AttachKprobe(syscall, vfsReadKprobe, -1)
	if err != nil {
		return errors.Wrapf(err, "attach entry %s", kprobeEntry)
	}
	return nil
}

func kretprobeSyscall(m *bpf.Module, syscall string, kprobeEntry string) error {
	vfsReadKprobe, err := m.LoadKprobe(kprobeEntry)
	if err != nil {
		return errors.Wrapf(err, "load entry %s", kprobeEntry)
	}

	err = m.AttachKretprobe(syscall, vfsReadKprobe, -1)
	if err != nil {
		return errors.Wrapf(err, "attach entry %s", kprobeEntry)
	}
	return nil
}

const (
	filePathLength    = 256
	containerIDLength = 128
)

func InitKprobeTable(id string) (*bpf.Module, *bpf.Table, error) {
	m := bpf.NewModule(sourceCode, []string{})

	if err := kprobeSyscall(m, "vfs_read", "trace_vfs_read_entry"); err != nil {
		return nil, nil, err
	}
	if err := kprobeSyscall(m, "vfs_readv", "trace_vfs_readv_entry"); err != nil {
		return nil, nil, err
	}
	if err := kprobeSyscall(m, "generic_file_splice_read", "trace_splice_read_entry"); err != nil {
		return nil, nil, err
	}
	if err := kretprobeSyscall(m, "vfs_read", "trace_read_return"); err != nil {
		return nil, nil, err
	}
	if err := kretprobeSyscall(m, "vfs_readv", "trace_read_return"); err != nil {
		return nil, nil, err
	}
	if err := kretprobeSyscall(m, "generic_file_splice_read", "trace_read_return"); err != nil {
		return nil, nil, err
	}
	if err := kprobeSyscall(m, "__do_fault", "trace_page_fault"); err != nil {
		return nil, nil, err
	}

	containerIDTable := bpf.NewTable(m.TableId("id_buf"), m)

	idSlice, err := unix.ByteSliceFromString(id)
	if err != nil {
		return nil, nil, err
	}

	var arr [containerIDLength]byte
	copy(arr[:], idSlice)
	containerID := ContainerID{
		buf: arr,
	}

	value := new(bytes.Buffer)
	err = binary.Write(value, binary.LittleEndian, containerID)
	if err != nil {
		log.L.Infof("[abin] failed to convert struct to byte slice: %v", containerID)
		return nil, nil, err
	}

	key := new(bytes.Buffer)
	var tmp uint32 = 0
	err = binary.Write(key, binary.LittleEndian, tmp)
	if err != nil {
		log.L.Infof("[abin] failed to convert int to byte slice: %v", 0)
		return nil, nil, err
	}

	if err := containerIDTable.Set(key.Bytes(), value.Bytes()); err != nil {
		return nil, nil, err
	}

	table := bpf.NewTable(m.TableId("fille_access_events"), m)

	return m, table, nil
}

type RawEventInfo struct {
	Command  [16]byte
	Path     [filePathLength]byte
	Position uint64
	Length   uint32
}

type ContainerID struct {
	buf [containerIDLength]byte
}
type EventInfo struct {
	Timestamp int64
	Command   string
	Path      string
	Position  uint64
	Size      uint32
}

type Client struct {
	Channel chan []byte
}

func (c *Client) GetEventInfo() (*EventInfo, error) {
	event := RawEventInfo{}

	data := <-c.Channel
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
	if err != nil {
		return nil, errors.Wrap(err, "decode received data")
	}

	return &EventInfo{
		Timestamp: time.Now().UnixMilli(),
		Command:   string(event.Command[:bytes.IndexByte(event.Command[:], 0)]),
		Path:      string(event.Path[:bytes.IndexByte(event.Path[:], 0)]),
		Position:  event.Position,
		Size:      event.Length,
	}, nil
}
