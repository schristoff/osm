package certificate

import (
	"math/rand"
	"sync"
	time "time"

	"github.com/openservicemesh/osm/pkg/announcements"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/k8s/events"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	// How much earlier (before expiration) should a certificate be renewed
	renewBeforeCertExpires = 30 * time.Second

	// So that we do not renew all certs at the same time - add noise.
	// These define the min and max of the seconds of noise to be added
	// to the early certificate renewal.
	minNoiseSeconds                    = 1
	maxNoiseSeconds                    = 5
	checkCertificateExpirationInterval = 5 * time.Second
)

var errCertNotFound = errors.New("failed to find cert")

type Manager struct {
	provider                    Provider
	ca                          *Certificate
	cache                       sync.Map
	msgBroker                   *messaging.Broker
	serviceCertValidityDuration time.Duration
}

//NewManager (todo:schristoff)
func NewManager(ca *Certificate, provider Provider, msgBroker *messaging.Broker, serviceCertValidityDuration time.Duration) *Manager {
	m := &Manager{
		ca:                          ca,
		provider:                    provider,
		cache:                       sync.Map{}, // NOTE: the empty struct is valid.
		msgBroker:                   msgBroker,
		serviceCertValidityDuration: serviceCertValidityDuration,
	}
	m.start(checkCertificateExpirationInterval)
	return m
}

func (m *Manager) deleteFromCache(cn CommonName) {
	m.cache.Delete(cn)
}

func (m *Manager) getFromCache(cn CommonName) *Certificate {
	if certInterface, exists := m.cache.Load(cn); exists {
		cert := certInterface.(*Certificate)
		log.Trace().Msgf("Certificate found in cache SerialNumber=%s", cert.GetSerialNumber())
		if ShouldRotate(cert) {
			log.Trace().Msgf("Certificate found in cache but has expired SerialNumber=%s", cert.GetSerialNumber())
			return nil
		}
		return cert
	}
	return nil
}

// IssueCertificate implements Manager and returns a newly issued certificate
func (m *Manager) IssueCertificate(cn CommonName, validityPeriod time.Duration) (*Certificate, error) {
	start := time.Now()

	if cert := m.getFromCache(cn); cert != nil {
		return cert, nil
	}

	cert, err := m.provider.IssueCertificate(cn, validityPeriod)
	if err != nil {
		return cert, err
	}

	m.cache.Store(cn, cert)

	log.Trace().Msgf("It took %+v to issue certificate with SerialNumber=%s", time.Since(start), cert.GetSerialNumber())

	return cert, nil
}

// ReleaseCertificate is called when a cert will no longer be needed and should be removed from the system.
func (m *Manager) ReleaseCertificate(cn CommonName) {
	log.Trace().Msgf("Releasing certificate %s", cn)
	m.deleteFromCache(cn)
}

// GetCertificate returns a certificate given its Common Name (CN)
func (m *Manager) GetCertificate(cn CommonName) (*Certificate, error) {
	if cert := m.getFromCache(cn); cert != nil {
		return cert, nil
	}
	return nil, errCertNotFound
}

// RotateCertificate implements Manager and rotates an existing
func (m *Manager) RotateCertificate(cn CommonName) (*Certificate, error) {
	start := time.Now()

	oldObj, ok := m.cache.Load(cn)
	if !ok {
		return nil, errors.Errorf("Old certificate does not exist for CN=%s", cn)
	}

	oldCert, ok := oldObj.(*Certificate)
	if !ok {
		return nil, errors.Errorf("unexpected type %T for old certificate does not exist for CN=%s", oldCert, cn)
	}

	newCert, err := m.provider.IssueCertificate(cn, m.serviceCertValidityDuration)
	if err != nil {
		return nil, err
	}

	m.cache.Store(cn, newCert)

	m.msgBroker.GetCertPubSub().Pub(events.PubSubMessage{
		Kind:   announcements.CertificateRotated,
		NewObj: newCert,
		OldObj: oldCert,
	}, announcements.CertificateRotated.String())

	log.Debug().Msgf("Rotated certificate (old SerialNumber=%s) with new SerialNumber=%s took %+v", oldCert.SerialNumber, newCert.SerialNumber, time.Since(start))

	return newCert, nil
}

// ListCertificates lists all certificates issued
func (m *Manager) ListCertificates() ([]*Certificate, error) {
	var certs []*Certificate
	m.cache.Range(func(cn interface{}, certInterface interface{}) bool {
		certs = append(certs, certInterface.(*Certificate))
		return true // continue the iteration
	})
	return certs, nil
}

// GetRootCertificate returns the root
func (m *Manager) GetRootCertificate() *Certificate {
	return m.ca
}

// Start starts a new facility for automatic certificate rotation.
func (m *Manager) start(checkInterval time.Duration) {
	// iterate over the list of certificates
	// when a cert needs to be rotated - call RotateCertificate()
	ticker := time.NewTicker(checkInterval)
	go func() {
		for {
			m.checkAndRotate()
			<-ticker.C
		}
	}()
}

//todo(schristoff): point
func (m *Manager) checkAndRotate() {
	certs, err := m.ListCertificates()
	if err != nil {
		log.Error().Err(err).Msgf("Error listing all certificates")
	}

	for _, cert := range certs {
		shouldRotate := ShouldRotate(cert)

		word := map[bool]string{true: "will", false: "will not"}[shouldRotate]
		log.Trace().Msgf("Cert %s %s be rotated; expires in %+v; renewBeforeCertExpires is %+v",
			cert.GetCommonName(),
			word,
			time.Until(cert.GetExpiration()),
			renewBeforeCertExpires)

		if shouldRotate {
			// Remove the certificate from the cache of the certificate manager
			newCert, err := m.RotateCertificate(cert.GetCommonName())
			if err != nil {
				// TODO(#3962): metric might not be scraped before process restart resulting from this error
				log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrRotatingCert)).
					Msgf("Error rotating cert SerialNumber=%s", cert.GetSerialNumber())
				continue
			}
			log.Trace().Msgf("Rotated cert SerialNumber=%s", newCert.GetSerialNumber())
		}
	}
}

// ShouldRotate determines whether a certificate should be rotated.
func ShouldRotate(cert *Certificate) bool {
	// The certificate is going to expire at a timestamp T
	// We want to renew earlier. How much earlier is defined in renewBeforeCertExpires.
	// We add a few seconds noise to the early renew period so that certificates that may have been
	// created at the same time are not renewed at the exact same time.

	intNoise := rand.Intn(maxNoiseSeconds-minNoiseSeconds) + minNoiseSeconds /* #nosec G404 */
	secondsNoise := time.Duration(intNoise) * time.Second
	return time.Until(cert.GetExpiration()) <= (renewBeforeCertExpires + secondsNoise)
}

// ListIssuedCertificates implements CertificateDebugger interface and returns the list of issued certificates.
func (m *Manager) ListIssuedCertificates() []*Certificate {
	var certs []*Certificate
	m.cache.Range(func(cnInterface interface{}, certInterface interface{}) bool {
		certs = append(certs, certInterface.(*Certificate))
		return true // continue the iteration
	})
	return certs
}
