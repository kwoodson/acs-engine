package certgen

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net"
	"sync"

	"github.com/Azure/acs-engine/pkg/api"
	tmpl "github.com/Azure/acs-engine/pkg/openshift/certgen/templates"
	"github.com/Azure/acs-engine/pkg/openshift/filesystem"
)

// Config represents an OpenShift configuration
type Config struct {
	templates              templateInterface
	ExternalMasterHostname string
	serial                 serial
	cas                    map[string]CertAndKey
	AuthSecret             string
	EncSecret              string
	Master                 *Master
	Bootstrap              KubeConfig
	ClusterUsername        string
	ClusterPassword        string
	AzureConfig            AzureConfig
}

// TemplateInterface created to simplify testing
type templateInterface interface {
	AssetNames() []string
	MustAsset(name string) []byte
}

type templates struct{}

// AssetNames returns the template AssetNames
func (templates) AssetNames() []string {
	return tmpl.AssetNames()
}

// MustAsset returns the template MustAsset []byte
func (templates) MustAsset(name string) []byte {
	return tmpl.MustAsset(name)
}

var _ templateInterface = &templates{}

// NewConfig returns a Config that holds Openshift data
func NewConfig(a *api.Properties, masterHostname string, masterExternalHostname string) *Config {
	c := &Config{
		templates: templates{},
		Master: &Master{
			Hostname: masterHostname,
			IPs: []net.IP{
				net.ParseIP(a.MasterProfile.FirstConsecutiveStaticIP),
			},
			Port: 8443,
		},
		ExternalMasterHostname: masterExternalHostname,
		ClusterUsername:        a.OrchestratorProfile.OpenShiftConfig.ClusterUsername,
		ClusterPassword:        a.OrchestratorProfile.OpenShiftConfig.ClusterPassword,
		AzureConfig: AzureConfig{
			TenantID:        a.AzProfile.TenantID,
			SubscriptionID:  a.AzProfile.SubscriptionID,
			AADClientID:     a.ServicePrincipalProfile.ClientID,
			AADClientSecret: a.ServicePrincipalProfile.Secret,
			ResourceGroup:   a.AzProfile.ResourceGroup,
			Location:        a.AzProfile.Location,
		},
	}

	return c
}

// AzureConfig represents the azure.conf configuration
type AzureConfig struct {
	TenantID        string
	SubscriptionID  string
	AADClientID     string
	AADClientSecret string
	ResourceGroup   string
	Location        string
}

// Master represents an OpenShift master configuration
type Master struct {
	Hostname string
	IPs      []net.IP
	Port     int16

	certs       map[string]CertAndKey
	etcdcerts   map[string]CertAndKey
	kubeconfigs map[string]KubeConfig
}

// CertAndKey is a certificate and key
type CertAndKey struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

type serial struct {
	m sync.Mutex
	i int64
}

func (s *serial) Get() *big.Int {
	s.m.Lock()
	defer s.m.Unlock()

	s.i++
	return big.NewInt(s.i)
}

// WriteMaster writes the config files for a Master node to a Filesystem.
func (c *Config) WriteMaster(fs filesystem.Filesystem) error {
	err := c.WriteMasterCerts(fs)
	if err != nil {
		return err
	}

	err = c.WriteMasterKeypair(fs)
	if err != nil {
		return err
	}

	err = c.WriteMasterKubeConfigs(fs)
	if err != nil {
		return err
	}

	err = c.WriteMasterFiles(fs)
	if err != nil {
		return err
	}

	err = c.WriteBootstrapCerts(fs)
	if err != nil {
		return err
	}

	return c.WriteNodeFiles(fs)
}

// WriteNode writes the config files for bootstrapping a node to a Filesystem.
func (c *Config) WriteNode(fs filesystem.Filesystem) error {
	err := c.WriteBootstrapCerts(fs)
	if err != nil {
		return err
	}

	err = c.WriteBootstrapKubeConfig(fs)
	if err != nil {
		return err
	}

	return c.WriteNodeFiles(fs)
}
