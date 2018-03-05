# Sargon

Sargon is a Docker authorization plugin that controls container creation.
It decides whether privileged containers can be created and checks whether
it is permitted to bind the requested host file system directories.

## Building

After cloning, change to the source directory and run

```text
  dep init
  dep ensure
  go build
```

## Usage

When started, the program reads its configuration file, disconnects iself
from the controlling terminal and continues running in the background. Error
reporting goes to the syslog facility `daemon`. The following options are
recognized:

* `-foreground`

  Run in the foreground. Send diagnostic output to the stderr.
  
* `-config=`*FILE*

  Read configuration from *FILE* instead of the default
  `/etc/docker/sargon.json`

In order to configure docker to consult sargon when creating new containers,
add the following option to its command line:

```text
  --authorization-plugin=sargon
```

## Configuration  

Sargon configuration is kept in JSON format in file `/etc/docker/sargon`.
The following keywords are recognized:

* `pidfile`

  Name of the PID file. Defaults to `/var/run/sargon.pid`.

* `mount`

  A list of directories on the file system, from which it is allowed
  to bind subdirectories to the containers being created. By default
  it is empty, meaning that binds are not allowed at all.

* `allowpriv`

  Allow the use of privileged containers. Defaults to `false`.
  
## Example

The following configuration allows users to bind only subdirectories located
under `/var/lib/mounts` and `/mnt`:

```json
{
    "pidfile":"/var/run/sargon.pid" ,
    "mount":[ "/var/lib/mounts", "/mnt" ]
}
```

  
