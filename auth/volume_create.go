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

type DriverMountPoint func (body *volume.VolumeCreateBody) (string, error)

var knownDrivers = map[string]DriverMountPoint{
	"local-persist": LocalPersistMpt,
}

func LocalPersistMpt(body *volume.VolumeCreateBody) (mpt string, err error) {
	mpt, prs := body.DriverOpts["mountpoint"]
	if !prs {
		err = errors.New("No mountpoint specified?")
	}
	return
}

func VolumeCreateAuth(acl access.ACL, req authorization.Request) authorization.Response {
	body := &volume.VolumeCreateBody{}
	if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(body); err != nil {
		return authorization.Response{Err: err.Error()}
	}
	diag.Debug("Create volume request: volume %s, driver %s, labels %v, options %v",
	      body.Name, body.Driver, body.Labels, body.DriverOpts)

	if body.Driver == "local" {
		// silently pass
	} else if getmpt := knownDrivers[body.Driver]; getmpt != nil {
		mpt, err := getmpt(body)
		if err != nil {
			diag.Error("can't get mountpoint from request %v: %s\n",
				   body, err.Error())
			return authorization.Response{Err: err.Error()}
		}
		res, id := acl.MountIsAllowed(mpt, false)
		diag.Trace("%s: binding to %s is %s by %s\n",
		      req.User, mpt, access.Resolution(res), id)
		if !res {
			return authorization.Response{Msg: "mounting " +
				                           mpt +
				                           " is not allowed"}
		}
	} else {
		diag.Error("unknown volume driver: %s, volume %s, labels %v, options %v\n",
			   body.Driver,
			   body.Name,
			   body.Labels,
			   body.DriverOpts)
	}		
	return authorization.Response{Allow: true}
}
