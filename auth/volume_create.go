package auth

import (
	"bytes"
	"errors"
	"encoding/json"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/docker/api/types/volume"
	"sargon/access"
	"sargon/diag"
)

type DriverOpts map[string]string
type DriverMountPoint func (opts DriverOpts) (string, error)

var knownDrivers = map[string]DriverMountPoint{
	"local-persist": LocalPersistMpt,
}

func LocalPersistMpt(opts DriverOpts) (mpt string, err error) {
	mpt, prs := opts["mountpoint"]
	if !prs {
		err = errors.New("No mountpoint specified?")
	}
	return
}

var ErrUnknownMountDriver = errors.New("Unknown mount driver")

func GetDriverMountPoint(name string, opts DriverOpts) (string, error) {
	if getmpt, ok := knownDrivers[name]; ok {
		return getmpt(opts)
	}
	return ``, ErrUnknownMountDriver
}

func VolumeCreateAuth(acl access.ACL, req authorization.Request) authorization.Response {
	body := &volume.CreateOptions{}
	if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(body); err != nil {
		return authorization.Response{Err: err.Error()}
	}
	diag.Debug("Create volume request: volume %s, driver %s, labels %#v, options %#v",
	      body.Name, body.Driver, body.Labels, body.DriverOpts)

	if body.Driver == "local" {
		// silently pass
	} else if mpt, err := GetDriverMountPoint(body.Driver, DriverOpts(body.DriverOpts)); err == nil {
		res, id := acl.MountIsAllowed(mpt, false)
		diag.Trace("%s: binding to %s is %s by %s\n",
		      req.User, mpt, access.Resolution(res), id)
		if !res {
			return authorization.Response{Msg: "mounting " +
							   mpt +
							   " is not allowed"}
		}
	} else if errors.Is(err, ErrUnknownMountDriver) {
		diag.Error("unknown volume driver: %s, volume %s, labels %v, options %v\n",
			   body.Driver,
			   body.Name,
			   body.Labels,
			   body.DriverOpts)
	} else {
		diag.Error("can't get mountpoint from request %#v: %s\n",
			   body, err.Error())
		return authorization.Response{Err: err.Error()}
	}
	return authorization.Response{Allow: true}
}
