package main

import (
	"strings"
	"path/filepath"
	"log"
	"github.com/docker/engine-api/types/mount"
	"strconv"
	"errors"
	"fmt"
)

type SargonACE struct {
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

type SargonACL []SargonACE

func NewSargonACL(n int) SargonACL {
	return make(SargonACL, n)
}

const (
	undef = iota
	reject
	accept
)

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
func (acl SargonACL) Len() int { return len(acl) }
func (acl SargonACL) Swap(i, j int) { acl[i], acl[j] = acl[j], acl[i] }
func (acl SargonACL) Less(i, j int) bool { return acl[i].Order < acl[j].Order }

func (ace SargonACE) ActionIsAllowed(action string) (result EvalResult) {
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

func (acl SargonACL) ActionIsAllowed(action string) (bool, string) {
	for _, ace := range acl {
		res := ace.ActionIsAllowed(action)
		if res.Defined() {
			return res.Accept(), ace.Id
		}
	}
	return false, "default policy"
}

func (ace SargonACE) CreatePrivilegedIsAllowed() EvalResult {
	if ace.AllowPriv == nil {
		return undef
	}
	if *ace.AllowPriv {
		return accept
	}
	return reject
}

func (acl SargonACL) CreatePrivilegedIsAllowed() (bool, string) {
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

func (ace SargonACE) CapIsAllowed(cap string) EvalResult {
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

func (acl SargonACL) CapIsAllowed(cap string) (bool, string) {
	cap = NormalizeCap(cap)
	for _, ace := range acl {
		res := ace.CapIsAllowed(cap)
		if res.Defined() {
			return res.Accept(), ace.Id
		}
	}
	return false, "default policy"
}

func realpath(s string) (string, error) {
        path, err := filepath.EvalSymlinks(s)
        if err != nil {
	        return s, err;
	}
        return filepath.Abs(path);
}

func (ace SargonACE) MountIsAllowed(dir string) EvalResult {
	if len(ace.Mount) == 0 {
		return undef
	}
	for _, mp := range ace.Mount {
		if strings.HasSuffix(mp, "/*") {
			if strings.HasPrefix(dir, mp[0:len(mp)-1]) {
				return accept
			}
		} else if strings.HasSuffix(mp, "/") {
			if mp == dir {
				return accept
			}
		} else if mp + "/" == dir {
			return accept
		}
	}
	return reject
}

func (acl SargonACL) MountIsAllowed(dir string) (bool, string) {
	mpt, err := realpath(dir)
	if err != nil {
		log.Printf("can't resolve path %s: %s\n", dir, err.Error())
		return false, "(bad path)"
	}
	for _, ace := range acl {
		res := ace.MountIsAllowed(mpt)
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

func (ace SargonACE) CheckMaxMemory(lim int64) EvalResult {
	if ace.MaxMemory == nil {
		return undef
	}
	if *ace.MaxMemory < lim {
		return reject
	}
	return accept
}

func (acl SargonACL) CheckMaxMemory(kw string, size int64) (bool, int64, string) {
	for _, ace := range acl {
		if res := ace.CheckMaxMemory(size); res.Defined() {
			return res.Accept(), *ace.MaxMemory, ace.Id
		}
	}
	return true, 0, "default policy"
}

func (ace SargonACE) CheckMaxKernelMemory(lim int64) EvalResult {
	if ace.MaxKernelMemory == nil {
		return undef
	}
	if *ace.MaxKernelMemory < lim {
		return reject
	}
	return accept
}

func (acl SargonACL) CheckMaxKernelMemory(kw string, size int64) (bool, int64, string) {
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

func (acl SargonACL) AllowCreate(body *createRequest, config *Config,
                                 username string) (bool, string) {
	// Check if privileged containers are allowed
	if body.HostConfig.Privileged {
		res, id := acl.CreatePrivilegedIsAllowed()
		trace("%s: privileged container creation is %s by %s\n",
		      username,	Resolution(res), id)
		if ! res {
			return false, "you are not allowed to create privileged containers"
		}
	}

	// Check capabilities
	for _, cap := range body.HostConfig.CapAdd {
		res, id := acl.CapIsAllowed(cap)
		trace("%s: adding capability %s is %s by %s\n",
		      username,	cap, Resolution(res), id)
		if ! res {
			return false, "capability " + cap + " is not allowed"
		}
	}

	// Check binds (old API)
	for _, b := range body.HostConfig.Binds {
		a := strings.SplitN(b, ":", 2)
		res, id := acl.MountIsAllowed(a[0])
		trace("%s: binding to %s is %s by %s\n",
		      username, a[0], Resolution(res), id)
		if ! res {
			return false, "mounting " + a[0] + " is not allowed"
		}
	}
	
	// Check mounts (new API)
	for _, m := range body.HostConfig.Mounts {
		if m.Type == mount.TypeBind {
			res, id := acl.MountIsAllowed(m.Source)
			trace("%s: mounting %s is %s by %s\n",
			      username, m.Source, Resolution(res), id)
			if ! res {
				return false, "mounting " + m.Source + " is not allowed"
			}
		}
	}
	
	// Check requested memory sizes
	ok, lim, id := acl.CheckMaxMemory("sargonMaxMemory", body.HostConfig.Memory)
	trace("%s: setting MaxMemory=%d is %s by %s\n",
	      username, body.HostConfig.Memory, Resolution(ok), id)
	if !ok {
		return false, "memory limit must be lower than or equal to " + fmt.Sprintf("%v",lim)
	}

	ok, lim, id = acl.CheckMaxMemory("sargonMaxKernelMemory", body.HostConfig.KernelMemory)
	trace("%s: MaxKernelMemory=%d is %s by %s\n",
	      username, body.HostConfig.Memory, Resolution(ok), id)
	if !ok {
		return false, "kernel memory limit must be lower than or equal to " + fmt.Sprintf("%v",lim)
        }

	return true, "Ok"
}

	
