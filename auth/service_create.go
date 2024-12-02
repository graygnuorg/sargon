package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/swarm"
	"sargon/access"
	"sargon/diag"
)

func ServiceCreateAuth(acl access.ACL, req authorization.Request) authorization.Response {
	var body swarm.ServiceSpec
	if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(&body); err != nil {
		return authorization.Response{Err: err.Error()}
	}
	contspec := body.TaskTemplate.ContainerSpec
	diag.Debug("Create service request: %#v", contspec)

	// Check capabilities
	for _, cap := range contspec.CapabilityAdd {
		res, id := acl.CapIsAllowed(cap)
		diag.Trace("%s: adding capability %s is %s by %s\n",
		      req.User,	cap, access.Resolution(res), id)
		if !res {
			diag.Trace("DENY ServiceCreate: capability %s is not allowed\n", cap)
			return authorization.Response{Msg: "capability " + cap + " is not allowed"}
		}
	}

	for _, mnt := range contspec.Mounts {
		diag.Debug("Mount: %#v", mnt)
		switch mnt.Type {
		case mount.TypeBind:
			return checkMountBind(acl, req, mnt)
		case mount.TypeVolume:
			return checkMountVolume(acl, req, mnt)
		default:
			diag.Error("Ignoring mount request of unsupported type: %#v",
				mnt)
		}
	}
	return authorization.Response{Allow: true}
}

func checkMountVolume(acl access.ACL, req authorization.Request, mnt mount.Mount) authorization.Response {
	if mnt.VolumeOptions != nil {
		diag.Debug("VolumeOptions: %#v", *mnt.VolumeOptions)
		if mnt.VolumeOptions.DriverConfig != nil {
			diag.Debug("DriverConfig: %#v", mnt.VolumeOptions.DriverConfig)
			if mnt.VolumeOptions.DriverConfig.Name == `local` {
				// silently ignore
			} else if mpt, err := GetDriverMountPoint(mnt.VolumeOptions.DriverConfig.Name, DriverOpts(mnt.VolumeOptions.DriverConfig.Options)); err == nil {
				res, id := acl.MountIsAllowed(mpt, mnt.ReadOnly)
				diag.Trace("%s: binding to %s is %s by %s\n",
					req.User, mpt, access.Resolution(res), id)
				if !res {
					return authorization.Response{Msg: "mounting " + mpt + " is not allowed"}
				}
			} else if errors.Is(err, ErrUnknownMountDriver) {
				diag.Error("unknown volume driver: %s, volume %s, options %#v\n",
					mnt.VolumeOptions.DriverConfig.Name,
					mnt.Source,
					mnt.VolumeOptions.DriverConfig.Options)
			} else {
				diag.Error("can't get mountpoint from request %#v: %s\n",
					mnt, err.Error())
				return authorization.Response{Err: err.Error()}
			}
		}
	}
	return authorization.Response{Allow: true}
}

func checkMountBind(acl access.ACL, req authorization.Request, mnt mount.Mount) authorization.Response {
	res, id := acl.MountIsAllowed(mnt.Source, mnt.ReadOnly)
	diag.Trace("%s: binding to %s is %s by %s\n",
		req.User, mnt.Source, access.Resolution(res), id)
	if !res {
		return authorization.Response{Msg: "mounting " + mnt.Source + " is not allowed"}
	}
	return authorization.Response{Allow: true}
}