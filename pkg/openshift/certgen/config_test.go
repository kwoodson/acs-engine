package certgen

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Azure/acs-engine/pkg/openshift/filesystem"
)

var fsdata = make(map[string]datastore)

type datastore struct {
	user  string
	group string
	mode  os.FileMode
}

type fakefilesystem struct{}

func (fakefilesystem) WriteFile(filename string, data []byte, fi filesystem.Fileinfo) error {
	// check that you've been asked to write the given file with sane permissions & owner
	// store the incoming files so we can compare them later on
	fsdata[filename] = datastore{fi.User, fi.Group, fi.Mode}
	// fmt.Printf("Filename: %v	User: %s	Group: %s	Permissions: %04o   string: %v\n", filename, fi.User, fi.Group, fi.Mode, fi.Mode.String())
	return nil
}

func (fakefilesystem) Mkdir(filename string, fi filesystem.Fileinfo) error {
	fmt.Printf("Filename: %v	User: %s	Group: %s	Permissions: %04o   string: %v\n", filename, fi.User, fi.Group, fi.Mode, fi.Mode.String())

	fsdata[filename] = datastore{fi.User, fi.Group, fi.Mode}
	return nil
}

func (fakefilesystem) Close() error {
	return nil
}

var _ filesystem.Filesystem = &fakefilesystem{}

func TestConfigFilePermissions(t *testing.T) {
	c := Config{
		templates: templates{},
		Master: &Master{
			Hostname: fmt.Sprintf("%s-master-%s-0", "test", "test"),
			IPs: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
	}

	err := c.PrepareMasterCerts()
	if err != nil {
		t.Fatal(err)
	}
	err = c.PrepareMasterKubeConfigs()
	if err != nil {
		t.Fatal(err)
	}
	err = c.PrepareMasterFiles()
	if err != nil {
		t.Fatal(err)
	}

	err = c.PrepareBootstrapKubeConfig()
	if err != nil {
		t.Fatal(err)
	}

	// create mock filesystem
	fs := fakefilesystem{}

	err = c.WriteMasterKubeConfigs(fs)
	if err != nil {
		t.Fatal(err)
	}

	err = c.WriteBootstrapKubeConfig(fs)
	if err != nil {
		t.Fatal(err)
	}

	err = c.WriteMasterKeypair(fs)
	if err != nil {
		t.Fatal(err)
	}

	err = c.WriteBootstrapCerts(fs)
	if err != nil {
		t.Fatal(err)
	}

	// write master files
	err = c.WriteMasterFiles(fs)
	if err != nil {
		t.Fatal(err)
	}

	// write node files
	err = c.WriteNodeFiles(fs)
	if err != nil {
		t.Fatal(err)
	}

	// AssetNames() only has a subset of the
	for _, fname := range c.templates.AssetNames() {
		fi := GetFileInfo(fname)
		parts := strings.Split(fname, "/")
		fname = filepath.Join(parts[1:]...)
		fmt.Printf("fname=>[%s]\n", fname)
		// Verify ownership and permissions are as expected
		if fi.User != fsdata[fname].user {
			t.Errorf("File: %s  User does not match.   user: %s  expected: %s", fname, fsdata[fname].user, fi.User)
		}
		if fi.Group != fsdata[fname].group {
			t.Errorf("File: %s  Group does not match.  group: %s  expected: %s", fname, fsdata[fname].group, fi.Group)
		}
		if fi.Mode != 0 && fi.Mode != fsdata[fname].mode {
			t.Errorf("File: %s  Mode does not match.   mode: %04o  expected: %04o", fname, fsdata[fname].mode, fi.Mode)
		}
		// Check for .key does _not_ have read or write
		if strings.Contains(fname, ".key") && fsdata[fname].mode&(1<<2) != 0 && fsdata[fname].mode&(1<<3) != 0 {
			t.Errorf("File: %s  Found Read or Write on key file. mode: %04o  expected: 0600", fname, fsdata[fname].mode)
		}
		if regexp.MustCompile("tmp$").MatchString(fname) && fi.Mode != os.FileMode(1770) {
			t.Errorf("File: %s  /tmp should have 1777 file mode.", fname)
		}
	}
}
