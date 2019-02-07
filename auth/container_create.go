package auth

import (
	"fmt"
	"strings"
	"bytes"
	"encoding/json"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/engine-api/types/container"
	"github.com/docker/engine-api/types/mount"
	"sargon/diag"
	"sargon/access"
)	

type createRequest struct {
	*container.Config
	HostConfig       *container.HostConfig
}

func ContainerCreateAuth (acl access.ACL, req authorization.Request) authorization.Response {
	diag.Debug("checking container parameters\n")
	body := &createRequest{}
	if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(body); err != nil {
		return authorization.Response{Err: err.Error()}
	}
		
	if res, msg := AllowCreate(acl, body, req.User); res == false {
		diag.Debug("DENY: %s\n", msg)
		return authorization.Response{Msg: msg}
	}	
	return authorization.Response{Allow: true}
}

func AllowCreate(acl access.ACL, body *createRequest, username string) (bool, string) {
	// Check if privileged containers are allowed
	if body.HostConfig.Privileged {
		res, id := acl.CreatePrivilegedIsAllowed()
		diag.Trace("%s: privileged container creation is %s by %s\n",
		      username,	access.Resolution(res), id)
		if ! res {
			return false, "you are not allowed to create privileged containers"
		}
	}

	// Check capabilities
	for _, cap := range body.HostConfig.CapAdd {
		res, id := acl.CapIsAllowed(cap)
		diag.Trace("%s: adding capability %s is %s by %s\n",
		      username,	cap, access.Resolution(res), id)
		if ! res {
			return false, "capability " + cap + " is not allowed"
		}
	}

	// Check binds (old API)
	for _, b := range body.HostConfig.Binds {
		a := strings.SplitN(b, ":", 2)
		res, id := acl.MountIsAllowed(a[0])
		diag.Trace("%s: binding to %s is %s by %s\n",
		      username, a[0], access.Resolution(res), id)
		if ! res {
			return false, "mounting " + a[0] + " is not allowed"
		}
	}
	
	// Check mounts (new API)
	for _, m := range body.HostConfig.Mounts {
		if m.Type == mount.TypeBind {
			res, id := acl.MountIsAllowed(m.Source)
			diag.Trace("%s: mounting %s is %s by %s\n",
			      username, m.Source, access.Resolution(res), id)
			if ! res {
				return false, "mounting " + m.Source + " is not allowed"
			}
		}
	}
	
	// Check requested memory sizes
	ok, lim, id := acl.CheckMaxMemory("sargonMaxMemory", body.HostConfig.Memory)
	diag.Trace("%s: setting MaxMemory=%d is %s by %s\n",
	      username, body.HostConfig.Memory, access.Resolution(ok), id)
	if !ok {
		return false, "memory limit must be lower than or equal to " + fmt.Sprintf("%v",lim)
	}

	ok, lim, id = acl.CheckMaxMemory("sargonMaxKernelMemory", body.HostConfig.KernelMemory)
	diag.Trace("%s: MaxKernelMemory=%d is %s by %s\n",
	      username, body.HostConfig.Memory, access.Resolution(ok), id)
	if !ok {
		return false, "kernel memory limit must be lower than or equal to " + fmt.Sprintf("%v",lim)
        }

	return true, "Ok"
}
	
