package access

import (
	"os"
	"strings"
	"path/filepath"
	"strconv"
	"errors"
	"regexp"
	"sargon/diag"
)

type ACE struct {
	Id string
	User []string
	Host []string
	Allow []string
	Deny []string
	Mount []string
	AllowPriv *bool
	MaxMemory *int64
	MaxKernelMemory *int64
	AllowCapability []string
	Order int
}

type ACL []ACE

const (
	undef = iota
	reject
	accept
)

func NewSargonACL(n int) ACL {
        return make(ACL, n)
}


type EvalResult int

func (e EvalResult) Accept() bool {
	return e == accept
}

func (e EvalResult) Reject() bool {
	return e == reject
}

func (e EvalResult) Undef() bool {
	return e == undef
}

func (e EvalResult) Defined() bool {
	return !e.Undef()
}

// Implementation of sort.Interface
func (acl ACL) Len() int { return len(acl) }
func (acl ACL) Swap(i, j int) { acl[i], acl[j] = acl[j], acl[i] }
func (acl ACL) Less(i, j int) bool { return acl[i].Order < acl[j].Order }

func (ace ACE) MatchUser(username string) bool {
	for _, user := range ace.User {
		if user == "ALL" || user == username {
			return true
		}
	}
	return false
}

func (ace ACE) ActionIsAllowed(action string) (result EvalResult) {
	for _, act := range ace.Allow {
		if act == action {
			return accept
		}
		if act == "ALL" {
			result = accept
			break
		}
	}
	for _, act := range ace.Deny {
		if act == action || act == "ALL" {
			result = reject
			break
		}
	}
	return
}

func (acl ACL) ActionIsAllowed(action string) (bool, string) {
	for _, ace := range acl {
		res := ace.ActionIsAllowed(action)
		if res.Defined() {
			return res.Accept(), ace.Id
		}
	}
	return false, "default policy"
}

func (ace ACE) CreatePrivilegedIsAllowed() EvalResult {
	if ace.AllowPriv == nil {
		return undef
	}
	if *ace.AllowPriv {
		return accept
	}
	return reject
}

func (acl ACL) CreatePrivilegedIsAllowed() (bool, string) {
	for _, ace := range acl {
		res := ace.CreatePrivilegedIsAllowed()
		if res.Defined() {
			return res.Accept(), ace.Id
		}
	}
	return false, "default policy"
}

func NormalizeCap(cap string) string {
	cap = strings.ToUpper(cap)
	if !strings.HasPrefix(cap, "CAP_") {
		cap = "CAP_" + cap
	}
	return cap
}

func (ace ACE) CapIsAllowed(cap string) EvalResult {
	if len(ace.AllowCapability) == 0 {
		return undef
	}
	for _, c := range ace.AllowCapability {
		if NormalizeCap(c) == cap || c == "ALL" {
			return accept
		}
	}
	return reject
}

func (acl ACL) CapIsAllowed(cap string) (bool, string) {
	cap = NormalizeCap(cap)
	for _, ace := range acl {
		res := ace.CapIsAllowed(cap)
		if res.Defined() {
			return res.Accept(), ace.Id
		}
	}
	return false, "default policy"
}

// Resolve symbolic links in name and convert it to absolute path.
// Tolerate non-existing file names or trailing name components: if
// name doesn't exist, strip off its last component and retry with
// the obtained directory name.  Continue until an existing prefix
// is found or all directory components have been tried.
func RealPath(name string) (path string, err error) {
	var tail []string
	path = name
	for path != "" {
		var s string
		s, err = filepath.EvalSymlinks(path)
		if err == nil {
			path, err = filepath.Abs(s)
			if err != nil {
				return
			}
			break
		} else if errors.Is(err, os.ErrNotExist) {
			tail = append([]string{filepath.Base(path)}, tail...)
			path = filepath.Dir(path)
			err = nil
	        } else {
			return;
		}
	}
	path = filepath.Join(append([]string{path}, tail...)...)
	return
}

var (
	mpointRe = regexp.MustCompile(`^(.+)\s*\(ro\)$`)
	volumeRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*`)
)

func (ace ACE) MountIsAllowed(dir string, ro bool) EvalResult {
	for _, mp := range ace.Mount {
		if res := mpointRe.FindStringSubmatch(mp); res != nil {
			if !ro {
				continue
			}
			mp = res[1]
		}
		if strings.HasSuffix(mp, "/*") {
			if strings.HasPrefix(dir, mp[0:len(mp)-1]) {
				return accept
			}
		} else if mp == dir {
			return accept
		}
	}
	return undef
}

func (acl ACL) MountIsAllowed(dir string, ro bool) (bool, string) {
	if volumeRe.FindStringIndex(dir) != nil {
		// Volume mounts are allowed
		return true, "volume mount"
	}
	dir = filepath.Clean(dir)
	mpt, err := RealPath(dir)
	if err != nil {
		diag.Error("can't resolve path %s: %s\n", dir, err.Error())
		return false, "(bad path)"
	}
	if mpt != dir {
		diag.Trace("%s is a symlink to %s\n", dir, mpt)
	}
	for _, ace := range acl {
		res := ace.MountIsAllowed(mpt, ro)
		if res.Defined() {
			return res.Accept(), ace.Id
		}
	}
	return false, "default policy"
}

func ConvSize(str string) (int64, error) {
	factor := 1
	if strings.HasSuffix(str, "k") || strings.HasSuffix(str, "K") {
		factor = 1024
		str = str[0:len(str)-1]
	} else if strings.HasSuffix(str, "m") || strings.HasSuffix(str, "M") {
		factor = 1024 * 1024;
		str = str[0:len(str)-1]
	} else if strings.HasSuffix(str, "g") || strings.HasSuffix(str, "G") {
		factor = 1024 * 1024 * 1024;
		str = str[0:len(str)-1]
	}
	n, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return n, err
	}
	if n < 0 {
		return -1, errors.New("value out of range")

	}
	return n * int64(factor), nil
}

func (ace ACE) CheckMaxMemory(lim int64) EvalResult {
	if ace.MaxMemory == nil {
		return undef
	}
	if *ace.MaxMemory < lim {
		return reject
	}
	return accept
}

func (acl ACL) CheckMaxMemory(kw string, size int64) (bool, int64, string) {
	for _, ace := range acl {
		if res := ace.CheckMaxMemory(size); res.Defined() {
			return res.Accept(), *ace.MaxMemory, ace.Id
		}
	}
	return true, 0, "default policy"
}

func (ace ACE) CheckMaxKernelMemory(lim int64) EvalResult {
	if ace.MaxKernelMemory == nil {
		return undef
	}
	if *ace.MaxKernelMemory < lim {
		return reject
	}
	return accept
}

func (acl ACL) CheckMaxKernelMemory(kw string, size int64) (bool, int64, string) {
	for _, ace := range acl {
		if res := ace.CheckMaxKernelMemory(size); res.Defined() {
			return res.Accept(), *ace.MaxKernelMemory, ace.Id
		}
	}
	return true, 0, "default policy"
}

func Resolution(b bool) string {
	if b {
		return "accepted"
	} else {
		return "rejected"
	}
}


	
