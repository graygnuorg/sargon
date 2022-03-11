# Sargon

Sargon is a docker authorization plugin that controls container creation.
It enables the administrator to exercise control over the containers that
users are allowed to create and decide whether to permit creation of
privileged containers, what parts of the host file system can be visible
to containers via bind or volume mechanism, what memory limits to apply,
etc.

User privileges are kept in LDAP.

## Building

After cloning, change to the source directory and run

```text
 make
```

To install the created binary, run (as root):

```text
 make install
```

By default, the *sargon* binary is installed to `/usr/local/bin`.  To
select another installation directory, use the `BINDIR` or `PREFIX`
variable.  The `BINDIR` variable specifies the directory to install
*sargon* to.  E.g. to istall it to `/usr/bin`, do

```text
 make install BINDIR=/usr/bin
```

Alternatively, you may use the `PREFIX` variable, which specifies the
directory where `bin` is located, e.g.:

```text
 make install PREFIX=/usr
``` 

## Usage

When started, the program reads its configuration file, disconnects itself
from the controlling terminal and continues running in the background. Error
reporting goes to the syslog facility `daemon`. The following options are
recognized:

* `-foreground`

  Run in the foreground. Send diagnostic output to the stderr.
  
* `-config=`*FILE*

  Read configuration from *FILE* instead of the default
  `/etc/docker/sargon.json`

* `-trace`
  Trace ACL entries and their effect.

* `-debug`

  Enable verbose debugging output

In order to configure docker to consult sargon when creating new containers,
add the following option to its command line:

```text
  --authorization-plugin=sargon
```

## Configuration  

Sargon configuration is kept in JSON format in file `/etc/docker/sargon.json`.
The following keywords are recognized:

* `pidfile`

  Name of the PID file. Defaults to `/var/run/sargon.pid`.

* `LdapConf`

  Colon-separated list of LDAP configuration files to look for. The first of
  them that exists will be read. Default is
  `/etc/ldap.conf:/etc/ldap/ldap.conf:/etc/openldap/ldap.conf`

* `LdapUser`

  Bind to LDAP using this DN. Defaults to empty string.
  This value overrides the `binddn` setting in `ldap.conf` file, which
  is the preferred way of configuring bind DN.

* `LdapPass`

  Bind to LDAP with this password. Defaults to empty string.
  This value overrides the password obtained from the `bindpwfile`
  setting in `ldap.conf` file.

* `LdapTLS`

  If `true`, start LDAP TLS session.

* `AnonymousUser`

  If docker connection is not authenticated, use this string as the user name.

## The `ldap.conf` file

After reading its main configuration file, *sargon* scans the LDAP
configuration path (see the `LdapConf` variable above). The first file that
exists and is readable is read. The format of the file is described in
detail in [ldap.conf(5)](https://www.openldap.org/software/man.cgi?query=ldap.conf).
The following keywords are recognized:

* `URI` ldap[si]://[name[:port]]

  URI of an LDAP server to which *sargon* should connect.
  
* `BASE` _base_

  Specifies the default base DN to use when performing ldap queries.
  
* `BINDDN` _dn_

  Specifies the default bind DN to use when performing ldap operations.

* `BINDPWFILE` _filename_

  Use the content of _filename_ as the password for simple
  authentication.  Note, that the file is read verbatim and is not parsed
  in any way.  In particular, beware of trailing newlines.

* `TLS_CACERT` _filename_

  Specifies the file that contains certificates for all of the Certificate
  Authorities the client will recognize.
  
* `TLS_CACERTDIR` _dirname_

  Specifies  the path of a directory that contains Certificate Authority
  certificates in separate individual files.
  The `TLS_CACERT` is always used before `TLS_CACERTDIR`.
  
* `TLS_CERT` _filename_

  Specifies the file that contains the client certificate.

* `TLS_KEY` _filename_

  Specifies the file that contains the private key for the
  certificate stored in the TLS_CERT file.
  
* `TLS_RANDFILE` _filename_

  Specifies the file to obtain random bits from, instead of the default
  `/dev/urandom` or `/dev/random`.
  
* `TLS_REQCERT` _level_

  Specifies  what  checks to perform on server certificates in a TLS session,
  if any. The _level_ is one of: `never`, `allow`, `try`, `demand`, or
  `try`.
  
## ACLs

Privileges for docker users are defined in the LDAP database in form of
`sargonACL` objects. Each such object defines privileges for a set of
users performing certain docker action on a set of servers. Each `sargonACL`
object must have the `cn` attribute, uniquely identifying the object.
It may also have one or more of the following attributes. Except as marked
with _(single)_, multiple attribute instances are allowed.

* `sargonUser`

  User to whom this entry applies. If the value begins with a percent
  sign, the rest of characters is treated as the name of a
  user group and the entry applies to all users in this group.

* `sargonHost`

  Host on which this entry takes effect. If the value starts with a plus
  sign, it is treated as the name of the NIS netgroup.
  
* `sargonAllow`

  Allowed action. The value must be one of the docker action keywords listed
  below, or the word `ALL` (uppercase) matching all actions.
  
* `sargonDeny`

  Denied action. The value must be one of the docker action keywords listed
  below, or the word `ALL` (uppercase) matching all actions. See below for
  a detailed discussion of how `sargonAllow` and `sargonDeny` policies
  operate.

* `sargonOrder` (single)

  An integer used to order multiple `sargonACL` entries. If not present, 0
  is assumed.

* `sargonMount`

  Name of the directory on the host filesystem that can be mounted inside
  a contained.

  If the name ends with `/*` only subdirectories of this directory can be
  mounted.

  If the directory name (with optional `/*` suffix) is followed by the
  string `(ro)`, only read-only mounting will be allowed.

  Prior to use, values of this attribute undergo variable expansion: any
  variable references in form `$`_V_ or `${`_V_`}` are replaced with the
  actual value of variable _V_. The following variables are defined:

  | Variable   | Expands to |
  | ---------- | ---------- |
  | `uid`      | User ID    |
  | `gid`      | Group ID   |
  | `name`     | User name  |
  | `home` or `dir` | Home directory |

  Undefined variables are left unexpanded.

* `sargonAllowPrivileged` (single)

  The word `TRUE` if the object allows creation of privileged containers.
  `FALSE` otherwise.
  
* `sargonMaxMemory` (single)

  Maximum size of the memory the container is allowed to use. The value is
  an integer optionally suffixed with `K`, `M`, or `G` (case-insensitive).
  
* `sargonMaxKernelMemory` (single)

  Limit on kernel memory usage. The value is an integer optionally suffixed
  with `K`, `M`, or `G` (case-insensitive).
  
* `sargonAllowCapability`

  Name of the linux capability that is allowed to use with the `--cap-add`
  docker option. See [capabilities(7)](http://man7.org/linux/man-pages/man7/capabilities.7.html), for a list of capability names.
  Names listed in this attribute are case-insensitive. The `CAP_` prefix is
  optional.

* `sargonNotBefore`

  A timestamp in the form `yyyymmddHHMMSSZ` that provides a start date/time
  for when this entry will be valid. Notice, that the timestamp must be in
  UTC.

* `sargonNotAfter`

  A timestamp in the form `yyyymmddHHMMSSZ` that provides an expiration
  date/time after which this entry ceases to be valid. Notice, that the
  timestamp must be in UTC.

When verifying each incoming request, *sargon* uses the following
algorithm:

1. Create LDAP filter with the user name and the names of the groups the
   user belongs to.
   For example, if the requesting user name is `smt`, and this user is
   member of the groups `staff`, `docker`, and `wheel`, then the LDAP
   filter will be:

```text
      (&(objectClass=sargonACL)
        (|(sargonUser=smt)
          (sargonUser=ALL)
          (sargonUser=%staff)
          (sargonUser=%docker)
          (sargonUser=%wheel)))
```	  

   Notice, that (1) the filter string is split in multiple indented lines
   for readability, and (2) the filter normally contains conditions that
   control validity of the entry using the `sargonNotBefore` and
   `sargonNotAfter` attributes. These conditions are omitted for clarity.

2. Execute LDAP query, get the response.

3. Iterate over the returned `sargonACL` objects, selecting only those
   with the value of `sargonHost` matching the server hostname, or (if
   the value starts with `+`) with the netgroup that matches
   the `(host,user,domain)` triplet.

   To match the netgroup, the libc function [innetgr(3)](http://man7.org/linux/man-pages/man3/setnetgrent.3.html) is used.

4. Sort the remaining entries by the value of their `sargonOrder` attribute
   in ascending order.

5. Start with the first returned object.

6. If the requested docker action is explicitly listed in one of its
   `sargonAllow` attributes, go to step 9.

7. Otherwise, if the object has one or more `sargonDeny` attributes and
   one of these contains the requested action or the meta-action `ALL`,
   then deny the request.

8. Advance to the next object, and restart from step 6.

9. Unless the requested action is `ContainerCreate`, authorize the request.

10. If creation of a privileged container is requested, consult the 
    `sargonAllowPrivileged` attribute. If it is `FALSE`, deny the request.
    Otherwise, advance to the next step.

11. If any additional linux capabilities are requested, check if all of
    them are listed in `sargonAllowCapability` attributes. If not, deny
    the request.

12. Check the requested binds and mounts. Check each source directory against
    each `sargonMount` attribute.  If the directory matches the attribute
    exactly, or if the attribute value ends with a `/*` and the source
    directory prefix matches the value, then the mount is allowed.
    Otherwise, the request is denied,

13. If the requested maximum memory is greater than the value of the
    `sargonMaxMemory` attribute, the request is denied.

14. If the requested maximum kernel memory is greater than the value of the
    `sargonMaxKernelMemory` attribute, the request is denied.

15. Otherwise, the request is authorized.

## Actions

The following values can be used in `sargonAllow` and `sargonDeny` attributes:

* `BuildPrune`
  Delete builder cache.

* `ConfigCreate`
  Create a config.

* `ConfigDelete`
  Delete a config.

* `ConfigInspect`
  Inspect a config.

* `ConfigList`
  List configs.

* `ConfigUpdate`
  Update a config.

* `ContainerArchive`
  Get an archive of a filesystem resource in a container.

* `ContainerArchiveInfo`
  Get information about files in a container.

* `ContainerAttach`
  Attach to a container.

* `ContainerAttachWebsocket`
  Attach to a container via a websocket.

* `ContainerChanges`
  Get changes on a container’s filesystem.

* `ContainerCreate`
  Create a container.

* `ContainerDelete`
  Remove a container.

* `ContainerExec`
  Create an exec instance.

* `ContainerExport`
  Export a container.

* `ContainerInspect`
  Inspect a container.

* `ContainerKill`
  Kill a container.

* `ContainerList`
  List containers.

* `ContainerLogs`
  Get container logs.

* `ContainerPause`
  Pause a container.

* `ContainerPrune`
  Delete stopped containers.

* `ContainerRename`
  Rename a container.

* `ContainerResize`
  Resize a container TTY.

* `ContainerRestart`
  Restart a container.

* `ContainerStart`
  Start a container.

* `ContainerStats`
  Get container stats based on resource usage.

* `ContainerStop`
  Stop a container.

* `ContainerTop`
  List processes running inside a container.

* `ContainerUnpause`
  Unpause a container.

* `ContainerUpdate`
  Update a container.

* `ContainerWait`
  Wait for a container.

* `DistributionInspect`
  Get image information from the registry.

* `ExecInspect`
  Inspect an exec instance.

* `ExecResize`
  Resize an exec instance.

* `ExecStart`
  Start an exec instance.

* `GetPluginPrivileges`
  Get plugin privileges.

* `ImageBuild`
  Build an image.

* `ImageCommit`
  Create a new image from a container.

* `ImageCreate`
  Create an image.

* `ImageDelete`
  Remove an image.

* `ImageGet`
  Export an image.

* `ImageGetAll`
  Export several images.

* `ImageHistory`
  Get the history of an image.

* `ImageInspect`
  Inspect an image.

* `ImageList`
  List Images.

* `ImageLoad`
  Import images.

* `ImagePrune`
  Delete unused images.

* `ImagePush`
  Push an image.

* `ImageSearch`
  Search images.

* `ImageTag`
  Tag an image.

* `NetworkConnect`
  Connect a container to a network.

* `NetworkCreate`
  Create a network.

* `NetworkDelete`
  Remove a network.

* `NetworkDisconnect`
  Disconnect a container from a network.

* `NetworkInspect`
  Inspect a network.

* `NetworkList`
  List networks.

* `NetworkPrune`
  Delete unused networks.

* `NodeDelete`
  Delete a node.

* `NodeInspect`
  Inspect a node.

* `NodeList`
  List nodes.

* `NodeUpdate`
  Update a node.

* `PluginCreate`
  Create a plugin.

* `PluginDelete`
  Remove a plugin.

* `PluginDisable`
  Disable a plugin.

* `PluginEnable`
  Enable a plugin.

* `PluginInspect`
  Inspect a plugin.

* `PluginList`
  List plugins.

* `PluginPull`
  Install a plugin.

* `PluginPush`
  Push a plugin.

* `PluginSet`
  Configure a plugin.

* `PluginUpgrade`
  Upgrade a plugin.

* `PutContainerArchive`
  Extract an archive of files or folders to a directory in a container.

* `SecretCreate`
  Create a secret.

* `SecretDelete`
  Delete a secret.

* `SecretInspect`
  Inspect a secret.

* `SecretList`
  List secrets.

* `SecretUpdate`
  Update a Secret.

* `ServiceCreate`
  Create a service.

* `ServiceDelete`
  Delete a service.

* `ServiceInspect`
  Inspect a service.

* `ServiceList`
  List services.

* `ServiceLogs`
  Get service logs.

* `ServiceUpdate`
  Update a service.

* `Session`
  Initialize interactive session.

* `SwarmInit`
  Initialize a new swarm.

* `SwarmInspect`
  Inspect swarm.

* `SwarmJoin`
  Join an existing swarm.

* `SwarmLeave`
  Leave a swarm.

* `SwarmUnlock`
  Unlock a locked manager.

* `SwarmUnlockkey`
  Get the unlock key.

* `SwarmUpdate`
  Update a swarm.

* `SystemAuth`
  Check auth configuration.

* `SystemDataUsage`
  Get data usage information.

* `SystemEvents`
  Monitor events.

* `SystemInfo`
  Get system information.

* `SystemPing`
  Ping.

* `SystemVersion`
  Get version.

* `TaskInspect`
  Inspect a task.

* `TaskList`
  List tasks.

* `TaskLogs`
  Get task logs.

* `VolumeCreate`
  Create a volume.

* `VolumeDelete`
  Remove a volume.

* `VolumeInspect`
  Inspect a volume.

* `VolumeList`
  List volumes.

* `VolumePrune`
  Delete unused volumes.


