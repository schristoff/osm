package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	mapset "github.com/deckarep/golang-set"
	xds_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	smiAccess "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/access/v1alpha3"
	smiSpecs "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/specs/v1alpha4"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyv1alpha1 "github.com/openservicemesh/osm/pkg/apis/policy/v1alpha1"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/policy"
	"github.com/openservicemesh/osm/pkg/service"
)

// validateFunc is a function type that accepts an AdmissionRequest and returns an AdmissionResponse.
/*
There are a few ways to utilize the Validator function:

1. return resp, nil

	In this case we simply return the raw resp. This allows for the most customization.

2. return nil, err

	In this case we convert the error to an AdmissionResponse.  If the error type is an AdmissionError, we
	convert accordingly, which allows for some customization of the AdmissionResponse. Otherwise, we set Allow to
	false and the status to the error message.

3. return nil, nil

	In this case we create a simple AdmissionResponse, with Allow set to true.

4. Note that resp, err will ignore the error. It assumes that you are returning nil for resp if there is an error

In all of the above cases we always populate the UID of the response from the request.

An example of a validator:

func FakeValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	o, n := &FakeObj{}, &FakeObj{}
	// If you need to compare against the old object
	if err := json.NewDecoder(bytes.NewBuffer(req.OldObject.Raw)).Decode(o); err != nil {
		return nil, err
	}

	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(n); err != nil {
		returrn nil, err
	}

	// validate the objects, potentially returning an error, or a more detailed AdmissionResponse.

	// This will set allow to true
	return nil, nil
}
*/
type validateFunc func(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error)

// policyValidator is a validator that has access to a policy
type policyValidator struct {
	policyClient policy.Controller
}

func trafficTargetValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	trafficTarget := &smiAccess.TrafficTarget{}
	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(trafficTarget); err != nil {
		return nil, err
	}

	if trafficTarget.Spec.Destination.Namespace != trafficTarget.Namespace {
		return nil, fmt.Errorf("The traffic target namespace (%s) must match spec.Destination.Namespace (%s)",
			trafficTarget.Namespace, trafficTarget.Spec.Destination.Namespace)
	}

	return nil, nil
}

// ingressBackendValidator validates the IngressBackend custom resource
func (kc *policyValidator) ingressBackendValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	ingressBackend := &policyv1alpha1.IngressBackend{}
	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(ingressBackend); err != nil {
		return nil, err
	}
	ns := ingressBackend.Namespace

	type setEntry struct {
		name string
		port int
	}

	backends := mapset.NewSet()
	var conflictString strings.Builder
	conflictingIngressBackends := mapset.NewSet()
	for _, backend := range ingressBackend.Spec.Backends {
		if unique := backends.Add(setEntry{backend.Name, backend.Port.Number}); !unique {
			return nil, fmt.Errorf("Duplicate backends detected with service name: %s and port: %d", backend.Name, backend.Port.Number)
		}

		fakeMeshSvc := service.MeshService{
			Name:       backend.Name,
			TargetPort: uint16(backend.Port.Number),
			Protocol:   backend.Port.Protocol,
		}

		if matchingPolicy := kc.policyClient.GetIngressBackendPolicy(fakeMeshSvc); matchingPolicy != nil && matchingPolicy.Name != ingressBackend.Name {
			// we've found a duplicate
			if unique := conflictingIngressBackends.Add(matchingPolicy); !unique {
				// we've already found the conflicts for this resource
				continue
			}
			conflicts := policy.DetectIngressBackendConflicts(*ingressBackend, *matchingPolicy)
			fmt.Fprintf(&conflictString, "[+] IngressBackend %s/%s conflicts with %s/%s:\n", ns, ingressBackend.ObjectMeta.GetName(), ns, matchingPolicy.ObjectMeta.GetName())
			for _, err := range conflicts {
				fmt.Fprintf(&conflictString, "%s\n", err)
			}
			fmt.Fprintf(&conflictString, "\n")
		}

		// Validate port
		switch strings.ToLower(backend.Port.Protocol) {
		case constants.ProtocolHTTP:
			// Valid

		case constants.ProtocolHTTPS:
			// Valid
			// If mTLS is enabled, verify there is an AuthenticatedPrincipal specified
			authenticatedSourceFound := false
			for _, source := range ingressBackend.Spec.Sources {
				if source.Kind == policyv1alpha1.KindAuthenticatedPrincipal {
					authenticatedSourceFound = true
					break
				}
			}

			if backend.TLS.SkipClientCertValidation && !authenticatedSourceFound {
				return nil, fmt.Errorf("HTTPS ingress with client certificate validation enabled must specify at least one 'AuthenticatedPrincipal` source")
			}

		default:
			return nil, fmt.Errorf("Expected 'port.protocol' to be 'http' or 'https', got: %s", backend.Port.Protocol)
		}
	}

	if conflictString.Len() != 0 {
		return nil, fmt.Errorf("duplicate backends detected\n%s", conflictString.String())
	}

	// Validate sources
	for _, source := range ingressBackend.Spec.Sources {
		switch source.Kind {
		// Add validation for source kinds here
		case policyv1alpha1.KindService:
			if source.Name == "" {
				return nil, fmt.Errorf("'source.name' not specified for source kind %s", policyv1alpha1.KindService)
			}
			if source.Namespace == "" {
				return nil, fmt.Errorf("'source.namespace' not specified for source kind %s", policyv1alpha1.KindService)
			}

		case policyv1alpha1.KindAuthenticatedPrincipal:
			if source.Name == "" {
				return nil, fmt.Errorf("'source.name' not specified for source kind %s", policyv1alpha1.KindAuthenticatedPrincipal)
			}

		case policyv1alpha1.KindIPRange:
			if _, _, err := net.ParseCIDR(source.Name); err != nil {
				return nil, fmt.Errorf("Invalid 'source.name' value specified for IPRange. Expected CIDR notation 'a.b.c.d/x', got '%s'", source.Name)
			}

		default:
			return nil, fmt.Errorf("Invalid 'source.kind' value specified. Must be one of: %s, %s, %s",
				policyv1alpha1.KindService, policyv1alpha1.KindAuthenticatedPrincipal, policyv1alpha1.KindIPRange)
		}
	}

	return nil, nil
}

// egressValidator validates the Egress custom resource
func egressValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	egress := &policyv1alpha1.Egress{}
	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(egress); err != nil {
		return nil, err
	}

	// Validate match references
	allowedAPIGroups := []string{smiSpecs.SchemeGroupVersion.String(), policyv1alpha1.SchemeGroupVersion.String()}
	upstreamTrafficSettingMatchCount := 0
	for _, m := range egress.Spec.Matches {
		switch *m.APIGroup {
		case smiSpecs.SchemeGroupVersion.String():
			switch m.Kind {
			case "HTTPRouteGroup":
				// no additional validation

			default:
				return nil, fmt.Errorf("Expected 'matches.kind' for match '%s' to be 'HTTPRouteGroup', got: %s", m.Name, m.Kind)
			}

		case policyv1alpha1.SchemeGroupVersion.String():
			switch m.Kind {
			case "UpstreamTrafficSetting":
				upstreamTrafficSettingMatchCount++

			default:
				return nil, fmt.Errorf("Expected 'matches.kind' for match '%s' to be 'UpstreamTrafficSetting', got: %s", m.Name, m.Kind)
			}

		default:
			return nil, fmt.Errorf("Expected 'matches.apiGroup' to be one of %v, got: %s", allowedAPIGroups, *m.APIGroup)
		}
	}

	// Can't have more than 1 UpstreamTrafficSetting match for an Egress policy
	if upstreamTrafficSettingMatchCount > 1 {
		return nil, fmt.Errorf("Cannot have more than 1 UpstreamTrafficSetting match")
	}

	return nil, nil
}

// upstreamTrafficSettingValidator validates the UpstreamTrafficSetting custom resource
func (kc *policyValidator) upstreamTrafficSettingValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	upstreamTrafficSetting := &policyv1alpha1.UpstreamTrafficSetting{}
	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(upstreamTrafficSetting); err != nil {
		return nil, err
	}

	ns := upstreamTrafficSetting.Namespace
	hostComponents := strings.Split(upstreamTrafficSetting.Spec.Host, ".")
	if len(hostComponents) < 2 {
		return nil, field.Invalid(field.NewPath("spec").Child("host"), upstreamTrafficSetting.Spec.Host, "invalid FQDN specified as host")
	}

	opt := policy.UpstreamTrafficSettingGetOpt{Host: upstreamTrafficSetting.Spec.Host}
	if matchingUpstreamTrafficSetting := kc.policyClient.GetUpstreamTrafficSetting(opt); matchingUpstreamTrafficSetting != nil && matchingUpstreamTrafficSetting.Name != upstreamTrafficSetting.Name {
		// duplicate detected
		return nil, fmt.Errorf("UpstreamTrafficSetting %s/%s conflicts with %s/%s since they have the same host %s", ns, upstreamTrafficSetting.ObjectMeta.GetName(), ns, matchingUpstreamTrafficSetting.ObjectMeta.GetName(), matchingUpstreamTrafficSetting.Spec.Host)
	}

	// Validate rate limiting config
	rl := upstreamTrafficSetting.Spec.RateLimit
	if rl != nil && rl.Local != nil && rl.Local.HTTP != nil {
		if _, ok := xds_type.StatusCode_name[int32(rl.Local.HTTP.ResponseStatusCode)]; !ok {
			return nil, fmt.Errorf("Invalid responseStatusCode %d. See https://www.envoyproxy.io/docs/envoy/latest/api-v3/type/v3/http_status.proto#enum-type-v3-statuscode for allowed values",
				rl.Local.HTTP.ResponseStatusCode)
		}
	}
	for _, route := range upstreamTrafficSetting.Spec.HTTPRoutes {
		if route.RateLimit != nil && route.RateLimit.Local != nil {
			if _, ok := xds_type.StatusCode_name[int32(route.RateLimit.Local.ResponseStatusCode)]; !ok {
				return nil, fmt.Errorf("Invalid responseStatusCode %d. See https://www.envoyproxy.io/docs/envoy/latest/api-v3/type/v3/http_status.proto#enum-type-v3-statuscode for allowed values",
					route.RateLimit.Local.ResponseStatusCode)
			}
		}
	}

	return nil, nil
}

type MRCInfo struct {
	storedMRC    *configv1alpha2.MeshRootCertificate
	suggestedMRC *configv1alpha2.MeshRootCertificate
	allStoredMRC []*configv1alpha2.MeshRootCertificate
}

// meshRootCertificateValidator validates the MeshRootCertificate CRD.
func (m MRCInfo) meshRootCertificateValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	mrcSetting := &configv1alpha2.MeshRootCertificate{}

	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(mrcSetting); err != nil {
		return nil, err
	}

	//todo(schristoff:)fake data for now
	m.allStoredMRC = []*configv1alpha2.MeshRootCertificate{}
	numAppliedMRC := len(m.allStoredMRC)

	switch req.Operation {
	case admissionv1.Delete:
		if numAppliedMRC == 1 {
			return nil, errors.Errorf("must have more than one Mesh Root Certificate to delete")
		}

		for _, v := range m.allStoredMRC {
			if mrcSetting.Name == v.Name {
				m.storedMRC = v
				return nil, m.validateMRCdelete()
				break
			}
		}
		return nil, errors.Errorf("cannot find mesh root certificate with name %v", mrcSetting.Name)

	case admissionv1.Create:
		//count only active, make sure no more than 2 active
		if !m.validateMRCcreate() {
			return nil, errors.Errorf("cannot create more than two active certificates")

		}

	case admissionv1.Update:
		for _, v := range m.allStoredMRC {
			if mrcSetting.Name == v.Name {
				m.storedMRC = v
				break
			} else {
				return nil, errors.Errorf("cannot find mesh root certificate with name %v", mrcSetting.Name)

			}
		}
		if !m.validateMRCupdate() {
			return nil, errors.Errorf("cannot transition %v in current state %v into state %v",
				m.storedMRC.Name, m.storedMRC.Status.State, m.suggestedMRC.Status.State)
		}
	}

	return nil, nil
}

func (m MRCInfo) validateMRCdelete() error {
	//Delete inactive or error only
	switch m.storedMRC.Status.State {
	case constants.MRCStateInactive, constants.MRCStateError:
		return nil
	default:
		return errors.Errorf("cannot delete certificate %v in stage %v", m.storedMRC.Name, m.storedMRC.Status.State)
	}
}

func (m MRCInfo) validateMRCupdate() bool {
	return m.validateMRCTransition()
}

func (m MRCInfo) validateMRCcreate() bool {
	return m.countActiveMRCs() < 2
}

func (m MRCInfo) validateMRCTransition() bool {
	allowedTransitions := map[string][]string{
		constants.MRCStateIssuingRollout:     {constants.MRCStateValidatingRollout, constants.MRCStateError},
		constants.MRCStateValidatingRollout:  {constants.MRCStateActive, constants.MRCStateError},
		constants.MRCStateActive:             {constants.MRCStateValidatingRollback, constants.MRCStateError},
		constants.MRCStateValidatingRollback: {constants.MRCStateIssuingRollback, constants.MRCStateError},
		constants.MRCStateIssuingRollback:    {constants.MRCStateInactive, constants.MRCStateError},
	}
	//look up storedMRC state key
	//applied state must be in the values for that key
	if allowedStates, ok := allowedTransitions[m.storedMRC.Status.State]; ok {
		for _, state := range allowedStates {
			//if going into active, safety check we have less than two
			if m.suggestedMRC.Status.State == constants.MRCStateActive {
				return m.countActiveMRCs() < 2
			}
			return m.suggestedMRC.Status.State == state
		}
	}
	// on false we could probably return []string of allowedStates for better
	// user exp. but that makes the logic less pretty
	return false
}

func (m MRCInfo) countActiveMRCs() int {
	var active int
	for _, mrc := range m.allStoredMRC {
		if mrc.Status.State == constants.MRCStateActive {
			active++
		}
	}
	// we could probably store names of active certs and
	// return them for a better user exp. ?
	return active
}
