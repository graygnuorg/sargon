package main
//#include <netdb.h>
import "C"

func InNetgroup(netgroup, host, user, domain string) bool {
	rc, err := C.innetgr(C.CString(netgroup),
	 		     C.CString(host),
		             C.CString(user),
	 	             C.CString(domain))
	if err != nil {
		return false
	}
	return rc != 0
}

