package server

import (
	"strings"
	"net/url"
	"github.com/docker/go-plugins-helpers/authorization"
	"sargon/diag"
	"sargon/access"
)	

func (srg *Sargon) AuthZReq(req authorization.Request) authorization.Response {

	uri, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	// Remove query parameters
	uri = (strings.SplitN(uri,"?",2))[0];

	if req.User == "" {
		req.User = srg.AnonymousUser
	}
	
	diag.Debug("checking %s request to %s from user %s\n",
              req.RequestMethod, uri, req.User)

	action, auth := GetAction(req.RequestMethod, uri)
	acl, err := srg.FindUser(req.User)
	if err != nil {
		return authorization.Response{Msg: "Autorization denied",
			                      Err: err.Error()}
	}

	diag.Debug("checking if action %s is allowed\n", action)
	ok, id := acl.ActionIsAllowed(action)
	diag.Trace("%s: action %s is %s by %s\n",
	      req.User, action, access.Resolution(ok), id)
	if !ok {
		return authorization.Response{Msg: "Action not allowed"}
	}

	if (auth != nil) {
		return auth(acl, req)
	}

	return authorization.Response{Allow: true}
}

func (srg *Sargon) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}
