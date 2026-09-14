//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// AtomicWrite opens every parent directory with O_NOFOLLOW. Keeping an open
// directory descriptor makes replacement independent of later pathname swaps.
// Parent directories must already exist and must be controlled by the operator.
// The temporary file starts at 0600; ownership/mode are applied before rename.
func AtomicWrite(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("destination must be a clean absolute path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return errors.New("destination parent is missing, inaccessible, or a symlink")
		}
		fd = next
	}
	defer unix.Close(fd)
	base := parts[len(parts)-1]
	var st unix.Stat_t
	e = unix.Fstatat(fd, base, &st, unix.AT_SYMLINK_NOFOLLOW)
	if e != nil && e != unix.ENOENT {
		return e
	}
	if e == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("destination must be a regular file, never a symlink")
	}
	// O_EXCL ensures an attacker cannot pre-create the temporary filename. It is
	// removed on every failure; rename publishes a complete file in one step.
	var temp string
	var out int
	for i := 0; i < 10; i++ {
		temp = ".ssm-" + randomName()
		out, e = unix.Openat(fd, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e == nil {
			break
		}
		if e != unix.EEXIST {
			return e
		}
	}
	if e != nil {
		return e
	}
	defer unix.Unlinkat(fd, temp, 0)
	f := os.NewFile(uintptr(out), temp)
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return e
	}
	if uid != -1 || gid != -1 {
		if e = f.Chown(uid, gid); e != nil {
			return e
		}
	}
	if e = f.Chmod(mode); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = unix.Renameat(fd, temp, fd, base); e != nil {
		return e
	}
	return unix.Fsync(fd)
}
func parseMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0600, nil
	}
	n, e := strconv.ParseUint(s, 8, 12)
	if e != nil || n > 0777 {
		return 0, errors.New("mode must be an octal permission such as 0600")
	}
	return os.FileMode(n), nil
}
