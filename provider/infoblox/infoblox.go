/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package infoblox

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/StackExchange/dnscontrol/v3/pkg/transform"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

const (
	// provider specific key to track if PTR record was already created or not for A records
	providerSpecificInfobloxPtrRecord = "infoblox-ptr-record-exists"
	infobloxCreate                    = "CREATE"
	infobloxDelete                    = "DELETE"
	infobloxUpdate                    = "UPDATE"
)

func isNotFoundError(err error) bool {
	_, ok := err.(*ibclient.NotFoundError)
	return ok
}

// StartupConfig clarifies the method signature
type StartupConfig struct {
	DomainFilter  endpoint.DomainFilter
	ZoneIDFilter  provider.ZoneIDFilter
	Host          string
	Port          int
	Username      string
	Password      string
	Version       string
	SSLVerify     bool
	DryRun        bool
	View          string
	MaxResults    int
	FQDNRegEx     string
	NameRegEx     string
	CreatePTR     bool
	CacheDuration int
}

// ProviderConfig implements the DNS provider for Infoblox.
type ProviderConfig struct {
	provider.BaseProvider
	client        ibclient.IBConnector
	domainFilter  endpoint.DomainFilter
	zoneIDFilter  provider.ZoneIDFilter
	view          string
	dryRun        bool
	fqdnRegEx     string
	createPTR     bool
	cacheDuration int
}

type infobloxRecordSet struct {
	obj ibclient.IBObject
	res interface{}
}

// ExtendedRequestBuilder implements a HttpRequestBuilder which sets
// additional query parameter on all get requests
type ExtendedRequestBuilder struct {
	fqdnRegEx  string
	nameRegEx  string
	maxResults int
	ibclient.WapiRequestBuilder
}

// NewExtendedRequestBuilder returns a ExtendedRequestBuilder which adds
// _max_results query parameter to all GET requests
func NewExtendedRequestBuilder(maxResults int, fqdnRegEx string, nameRegEx string) *ExtendedRequestBuilder {
	return &ExtendedRequestBuilder{
		fqdnRegEx:  fqdnRegEx,
		nameRegEx:  nameRegEx,
		maxResults: maxResults,
	}
}

// BuildRequest prepares the api request. it uses BuildRequest of
// WapiRequestBuilder and then add the _max_requests parameter
func (mrb *ExtendedRequestBuilder) BuildRequest(t ibclient.RequestType, obj ibclient.IBObject, ref string, queryParams *ibclient.QueryParams) (req *http.Request, err error) {
	req, err = mrb.WapiRequestBuilder.BuildRequest(t, obj, ref, queryParams)
	if req.Method == "GET" {
		query := req.URL.Query()
		if mrb.maxResults > 0 {
			query.Set("_max_results", strconv.Itoa(mrb.maxResults))
		}
		_, zoneAuthQuery := obj.(*ibclient.ZoneAuth)
		if zoneAuthQuery && t == ibclient.GET && mrb.fqdnRegEx != "" {
			query.Set("fqdn~", mrb.fqdnRegEx)
		}

		// if we are not doing a ZoneAuth query, support the name filter
		if !zoneAuthQuery && mrb.nameRegEx != "" {
			query.Set("name~", mrb.nameRegEx)
		}

		req.URL.RawQuery = query.Encode()
	}
	return
}

// NewInfobloxProvider creates a new Infoblox provider.
func NewInfobloxProvider(ibStartupCfg StartupConfig) (*ProviderConfig, error) {
	hostCfg := ibclient.HostConfig{
		Host:    ibStartupCfg.Host,
		Port:    strconv.Itoa(ibStartupCfg.Port),
		Version: ibStartupCfg.Version,
	}

	authCfg := ibclient.AuthConfig{
		Username: ibStartupCfg.Username,
		Password: ibStartupCfg.Password,
	}

	httpPoolConnections := lookupEnvAtoi("EXTERNAL_DNS_INFOBLOX_HTTP_POOL_CONNECTIONS", 10)
	httpRequestTimeout := lookupEnvAtoi("EXTERNAL_DNS_INFOBLOX_HTTP_REQUEST_TIMEOUT", 60)

	transportConfig := ibclient.NewTransportConfig(
		strconv.FormatBool(ibStartupCfg.SSLVerify),
		httpRequestTimeout,
		httpPoolConnections,
	)

	var (
		requestBuilder ibclient.HttpRequestBuilder
		err            error
	)
	if ibStartupCfg.MaxResults != 0 || ibStartupCfg.FQDNRegEx != "" || ibStartupCfg.NameRegEx != "" {
		// use our own HttpRequestBuilder which sets _max_results parameter on GET requests
		requestBuilder = NewExtendedRequestBuilder(ibStartupCfg.MaxResults, ibStartupCfg.FQDNRegEx, ibStartupCfg.NameRegEx)
	} else {
		// use the default HttpRequestBuilder of the infoblox client
		requestBuilder, err = ibclient.NewWapiRequestBuilder(hostCfg, authCfg)
		if err != nil {
			return nil, err
		}
	}

	requestor := &ibclient.WapiHttpRequestor{}

	client, err := ibclient.NewConnector(hostCfg, authCfg, transportConfig, requestBuilder, requestor)
	if err != nil {
		return nil, err
	}

	providerCfg := &ProviderConfig{
		client:        client,
		domainFilter:  ibStartupCfg.DomainFilter,
		zoneIDFilter:  ibStartupCfg.ZoneIDFilter,
		dryRun:        ibStartupCfg.DryRun,
		view:          ibStartupCfg.View,
		fqdnRegEx:     ibStartupCfg.FQDNRegEx,
		createPTR:     ibStartupCfg.CreatePTR,
		cacheDuration: ibStartupCfg.CacheDuration,
	}

	return providerCfg, nil
}

// Records gets the current records.
func (p *ProviderConfig) Records(_ context.Context) (endpoints []*endpoint.Endpoint, err error) {
	zones, err := p.zones()
	if err != nil {
		return nil, fmt.Errorf("could not fetch zones: %w", err)
	}

	for _, zone := range zones {
		log.Debugf("fetch records from zone '%s'", zone.Fqdn)

		view := p.view
		if view == "" {
			view = "default"
		}
		searchParams := ibclient.NewQueryParams(
			false,
			map[string]string{
				"zone": zone.Fqdn,
				"view": view,
			},
		)

		var resA []ibclient.RecordA
		objA := ibclient.NewEmptyRecordA()
		objA.View = p.view
		objA.Zone = zone.Fqdn
		err = p.client.GetObject(objA, "", searchParams, &resA)
		if err != nil && !isNotFoundError(err) {
			return nil, fmt.Errorf("could not fetch A records from zone '%s': %w", zone.Fqdn, err)
		}
		for _, res := range resA {
			// Check if endpoint already exists and add to existing endpoint if it does
			foundExisting := false
			for _, ep := range endpoints {
				if ep.DNSName == res.Name && ep.RecordType == endpoint.RecordTypeA {
					foundExisting = true
					duplicateTarget := false

					for _, t := range ep.Targets {
						if t == res.Ipv4Addr {
							duplicateTarget = true
							break
						}
					}

					if duplicateTarget {
						log.Debugf("A duplicate target '%s' found for existing A record '%s'", res.Ipv4Addr, ep.DNSName)
					} else {
						log.Debugf("Adding target '%s' to existing A record '%s'", res.Ipv4Addr, res.Name)
						ep.Targets = append(ep.Targets, res.Ipv4Addr)
					}
					break
				}
			}
			if !foundExisting {
				newEndpoint := endpoint.NewEndpointWithTTL(
					res.Name,
					endpoint.RecordTypeA,
					endpoint.TTL(int(res.Ttl)),
					res.Ipv4Addr,
				)
				if p.createPTR {
					newEndpoint.WithProviderSpecific(providerSpecificInfobloxPtrRecord, "true")
				}
				endpoints = append(endpoints, newEndpoint)
			}
		}
		// sort targets so that they are always in same order, as infoblox might return them in different order
		for _, ep := range endpoints {
			sort.Sort(ep.Targets)
		}

		// Include Host records since they should be treated synonymously with A records
		var resH []ibclient.HostRecord
		objH := ibclient.NewEmptyHostRecord()
		objH.View = p.view
		objH.Zone = zone.Fqdn
		err = p.client.GetObject(objH, "", searchParams, &resH)
		if err != nil && !isNotFoundError(err) {
			return nil, fmt.Errorf("could not fetch host records from zone '%s': %w", zone.Fqdn, err)
		}
		for _, res := range resH {
			for _, ip := range res.Ipv4Addrs {
				log.Debugf("Record='%s' A(H):'%s'", res.Name, ip.Ipv4Addr)

				// host record is an abstraction in infoblox that combines A and PTR records
				// for any host record we already should have a PTR record in infoblox, so mark it as created
				newEndpoint := endpoint.NewEndpointWithTTL(
					res.Name,
					endpoint.RecordTypeA,
					endpoint.TTL(int(res.Ttl)),
					ip.Ipv4Addr,
				)
				if p.createPTR {
					newEndpoint.WithProviderSpecific(providerSpecificInfobloxPtrRecord, "true")
				}
				endpoints = append(endpoints, newEndpoint)
			}
		}

		var resC []ibclient.RecordCNAME
		objC := ibclient.NewEmptyRecordCNAME()
		objC.View = p.view
		objC.Zone = zone.Fqdn
		err = p.client.GetObject(objC, "", searchParams, &resC)
		if err != nil && !isNotFoundError(err) {
			return nil, fmt.Errorf("could not fetch CNAME records from zone '%s': %w", zone.Fqdn, err)
		}
		for _, res := range resC {
			log.Debugf("Record='%s' CNAME:'%s'", res.Name, res.Canonical)
			endpoints = append(endpoints, endpoint.NewEndpointWithTTL(
				res.Name,
				endpoint.RecordTypeCNAME,
				endpoint.TTL(int(res.Ttl)),
				res.Canonical,
			),
			)

		}

		if p.createPTR {
			// infoblox doesn't accept reverse zone's fqdn, and instead expects .in-addr.arpa zone
			// so convert our zone fqdn (if it is a correct cidr block) into in-addr.arpa address and pass that into infoblox
			// example: 10.196.38.0/24 becomes 38.196.10.in-addr.arpa
			arpaZone, err := transform.ReverseDomainName(zone.Fqdn)
			if err == nil {
				var resP []ibclient.RecordPTR
				objP := ibclient.NewEmptyRecordPTR()
				objP.Zone = arpaZone
				objP.View = p.view
				err = p.client.GetObject(objP, "", searchParams, &resP)
				if err != nil && !isNotFoundError(err) {
					return nil, fmt.Errorf("could not fetch PTR records from zone '%s': %w", zone.Fqdn, err)
				}
				for _, res := range resP {
					endpoints = append(endpoints, endpoint.NewEndpointWithTTL(res.PtrdName,
						endpoint.RecordTypePTR,
						endpoint.TTL(int(res.Ttl)),
						res.Ipv4Addr,
					),
					)
				}
			}
		}

		var resT []ibclient.RecordTXT
		objT := ibclient.NewEmptyRecordTXT()
		objT.View = p.view
		objT.Zone = zone.Fqdn
		err = p.client.GetObject(objT, "", searchParams, &resT)
		if err != nil && !isNotFoundError(err) {
			return nil, fmt.Errorf("could not fetch TXT records from zone '%s': %w", zone.Fqdn, err)
		}
		for _, res := range resT {
			// The Infoblox API strips enclosing double quotes from TXT records lacking whitespace.
			// Unhandled, the missing double quotes would break the extractOwnerID method of the registry package.
			if _, err := strconv.Unquote(res.Text); err != nil {
				res.Text = strconv.Quote(res.Text)
			}

			foundExisting := false

			for _, ep := range endpoints {
				if ep.DNSName == res.Name && ep.RecordType == endpoint.RecordTypeTXT {
					foundExisting = true
					duplicateTarget := false

					for _, t := range ep.Targets {
						if t == res.Text {
							duplicateTarget = true
							break
						}
					}

					if duplicateTarget {
						log.Debugf("A duplicate target '%s' found for existing TXT record '%s'", res.Text, ep.DNSName)
					} else {
						log.Debugf("Adding target '%s' to existing TXT record '%s'", res.Text, res.Name)
						ep.Targets = append(ep.Targets, res.Text)
					}
					break
				}
			}
			if !foundExisting {
				log.Debugf("Record='%s' TXT:'%s'", res.Name, res.Text)
				newEndpoint := endpoint.NewEndpointWithTTL(
					res.Name,
					endpoint.RecordTypeTXT,
					endpoint.TTL(int(res.Ttl)),
					res.Text,
				)
				endpoints = append(endpoints, newEndpoint)
			}
		}
	}

	// update A records that have PTR record created for them already
	if p.createPTR {
		// save all ptr records into map for a quick look up
		ptrRecordsMap := make(map[string]bool)
		for _, ptrRecord := range endpoints {
			if ptrRecord.RecordType != endpoint.RecordTypePTR {
				continue
			}
			ptrRecordsMap[ptrRecord.DNSName] = true
		}

		for i := range endpoints {
			if endpoints[i].RecordType != endpoint.RecordTypeA {
				continue
			}
			// if PTR record already exists for A record, then mark it as such
			if ptrRecordsMap[endpoints[i].DNSName] {
				found := false
				for j := range endpoints[i].ProviderSpecific {
					if endpoints[i].ProviderSpecific[j].Name == providerSpecificInfobloxPtrRecord {
						endpoints[i].ProviderSpecific[j].Value = "true"
						found = true
					}
				}
				if !found {
					endpoints[i].WithProviderSpecific(providerSpecificInfobloxPtrRecord, "true")
				}
			}
		}
	}
	log.Debugf("fetched %d records from infoblox", len(endpoints))
	return endpoints, nil
}

func (p *ProviderConfig) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	// Update user specified TTL (0 == disabled)
	for _, ep := range endpoints {
		if !ep.RecordTTL.IsConfigured() {
			ep.RecordTTL = endpoint.TTL(p.cacheDuration)
		}
	}

	if !p.createPTR {
		return endpoints, nil
	}

	// for all A records, we want to create PTR records
	// so add provider specific property to track if the record was created or not
	for i := range endpoints {
		if endpoints[i].RecordType == endpoint.RecordTypeA {
			found := false
			for j := range endpoints[i].ProviderSpecific {
				if endpoints[i].ProviderSpecific[j].Name == providerSpecificInfobloxPtrRecord {
					endpoints[i].ProviderSpecific[j].Value = "true"
					found = true
				}
			}
			if !found {
				endpoints[i].WithProviderSpecific(providerSpecificInfobloxPtrRecord, "true")
			}
		}
	}

	return endpoints, nil
}

func newIBChanges(action string, eps []*endpoint.Endpoint) []*infobloxChange {
	changes := make([]*infobloxChange, 0, len(eps))
	for _, ep := range eps {
		for _, target := range ep.Targets {
			newEp := ep.DeepCopy()
			newEp.Targets = endpoint.Targets{target}
			changes = append(changes, &infobloxChange{
				Action:   action,
				Endpoint: newEp,
			})
		}
	}

	return changes
}

func zonePointerConverter(in []ibclient.ZoneAuth) []*ibclient.ZoneAuth {
	out := make([]*ibclient.ZoneAuth, len(in))
	for i := range in {
		out[i] = &in[i]
	}
	return out
}

// submitChanges sends changes to Infoblox
func (p *ProviderConfig) submitChanges(changes []*infobloxChange) error {
	// return early if there is nothing to change
	if len(changes) == 0 {
		return nil
	}

	zones, err := p.zones()
	if err != nil {
		return fmt.Errorf("could not fetch zones: %w", err)
	}

	changesByZone := p.ChangesByZone(zonePointerConverter(zones), changes)
	for _, changes := range changesByZone {
		for _, change := range changes {
			record, err := p.buildRecord(change)
			if err != nil {
				return fmt.Errorf("could not build record: %w", err)
			}
			refId, logFields, err := getRefID(record)
			if err != nil {
				return err
			}
			logFields["action"] = change.Action
			log.WithFields(logFields).Info("Changing record.")
			switch change.Action {
			case infobloxCreate:
				_, err = p.client.CreateObject(record.obj)
				if err != nil {
					return err
				}
			case infobloxDelete:
				_, err = p.client.DeleteObject(refId)
				if err != nil {
					return err
				}
			case infobloxUpdate:
				_, err = p.client.UpdateObject(record.obj, refId)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown action '%s'", change.Action)
			}
		}
	}

	return nil
}

func getRefID(record *infobloxRecordSet) (string, log.Fields, error) {
	t := reflect.TypeOf(record.obj).Elem().Name()
	l := log.Fields{
		"type": t,
	}
	switch t {
	case "RecordA":
		l["record"] = record.obj.(*ibclient.RecordA).Name
		l["ttl"] = record.obj.(*ibclient.RecordA).Ttl
		l["target"] = record.obj.(*ibclient.RecordA).Ipv4Addr
		for _, r := range *record.res.(*[]ibclient.RecordA) {
			return r.Ref, l, nil
		}
		return "", l, nil
	case "RecordTXT":
		l["record"] = record.obj.(*ibclient.RecordTXT).Name
		l["ttl"] = record.obj.(*ibclient.RecordTXT).Ttl
		l["target"] = record.obj.(*ibclient.RecordTXT).Text
		for _, r := range *record.res.(*[]ibclient.RecordTXT) {
			return r.Ref, l, nil
		}
		return "", l, nil
	case "RecordCNAME":
		l["record"] = record.obj.(*ibclient.RecordCNAME).Name
		l["ttl"] = record.obj.(*ibclient.RecordCNAME).Ttl
		l["target"] = record.obj.(*ibclient.RecordCNAME).Canonical
		for _, r := range *record.res.(*[]ibclient.RecordCNAME) {
			return r.Ref, l, nil
		}
		return "", l, nil
	case "RecordPTR":
		l["record"] = record.obj.(*ibclient.RecordPTR).Name
		l["ttl"] = record.obj.(*ibclient.RecordPTR).Ttl
		l["target"] = record.obj.(*ibclient.RecordPTR).PtrdName
		for _, r := range *record.res.(*[]ibclient.RecordPTR) {
			return r.Ref, l, nil
		}
		return "", l, nil
	}
	return "", l, fmt.Errorf("unknown type '%s'", t)
}

// ApplyChanges applies the given changes.
func (p *ProviderConfig) ApplyChanges(_ context.Context, changes *plan.Changes) error {

	_ = func(changes *plan.Changes) []*endpoint.Endpoint {
		mUpdateOldTargets := map[string]bool{}
		mUpdateNewTargets := map[string]bool{}
		deleteDiffEp := &endpoint.Endpoint{}

		for _, ep := range changes.UpdateNew {
			for _, target := range ep.Targets {
				mUpdateNewTargets[target] = true
			}
		}

		for _, ep := range changes.UpdateOld {
			for _, target := range ep.Targets {
				mUpdateOldTargets[target] = true
			}
		}

		for target, _ := range mUpdateOldTargets {
			if !mUpdateNewTargets[target] {
				deleteDiffEp.Targets = append(deleteDiffEp.Targets, target)
			}
		}

		return []*endpoint.Endpoint{deleteDiffEp}
	}

	combinedChanges := make([]*infobloxChange, 0, len(changes.Create)+len(changes.UpdateNew)+len(changes.Delete))

	combinedChanges = append(combinedChanges, newIBChanges(infobloxCreate, changes.Create)...)
	combinedChanges = append(combinedChanges, newIBChanges(infobloxUpdate, changes.UpdateNew)...)
	combinedChanges = append(combinedChanges, newIBChanges(infobloxDelete, changes.Delete)...)

	return p.submitChanges(combinedChanges)
}

func (p *ProviderConfig) zones() ([]ibclient.ZoneAuth, error) {
	var res, result []ibclient.ZoneAuth
	obj := ibclient.NewZoneAuth(
		ibclient.ZoneAuth{
			View: p.view,
		},
	)
	err := p.client.GetObject(obj, "", nil, &res)
	if err != nil && !isNotFoundError(err) {
		return nil, err
	}

	for _, zone := range res {
		if !p.domainFilter.Match(zone.Fqdn) {
			continue
		}

		if !p.zoneIDFilter.Match(zone.Ref) {
			continue
		}

		result = append(result, zone)
	}

	return result, nil
}

type infobloxChange struct {
	Action   string
	Endpoint *endpoint.Endpoint
}

func (p *ProviderConfig) ChangesByZone(zones []*ibclient.ZoneAuth, changeSets []*infobloxChange) map[string][]*infobloxChange {
	changes := make(map[string][]*infobloxChange)
	for _, z := range zones {
		changes[z.Fqdn] = []*infobloxChange{}
	}

	for _, c := range changeSets {
		zone := p.findZone(zones, c.Endpoint.DNSName)
		if zone.Fqdn == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected", c.Endpoint.DNSName)
			continue
		}
		changes[zone.Fqdn] = append(changes[zone.Fqdn], c)

		if p.createPTR && c.Endpoint.RecordType == endpoint.RecordTypeA {
			reverseZone := p.findReverseZone(zones, c.Endpoint.Targets[0])
			if reverseZone == nil {
				logrus.Debugf("Ignoring changes to '%s' because a suitable Infoblox DNS reverse zone was not found.", c.Endpoint.Targets)
				continue
			}
			copyEp := *c.Endpoint
			copyEp.RecordType = endpoint.RecordTypePTR
			changes[reverseZone.Fqdn] = append(changes[reverseZone.Fqdn], &infobloxChange{c.Action, &copyEp})
		}
	}
	return changes
}

func (p *ProviderConfig) findZone(zones []*ibclient.ZoneAuth, name string) *ibclient.ZoneAuth {
	var result *ibclient.ZoneAuth

	// Go through every zone looking for the longest name (i.e. most specific) as a matching suffix
	for idx := range zones {
		zone := zones[idx]
		if strings.HasSuffix(name, "."+zone.Fqdn) {
			if result == nil || len(zone.Fqdn) > len(result.Fqdn) {
				result = zone
			}
		} else if strings.EqualFold(name, zone.Fqdn) {
			if result == nil || len(zone.Fqdn) > len(result.Fqdn) {
				result = zone
			}
		}
	}
	return result
}

func (p *ProviderConfig) findReverseZone(zones []*ibclient.ZoneAuth, name string) *ibclient.ZoneAuth {
	ip := net.ParseIP(name)
	networks := map[int]*ibclient.ZoneAuth{}
	maxMask := 0

	for i, zone := range zones {
		_, rZoneNet, err := net.ParseCIDR(zone.Fqdn)
		if err != nil {
			logrus.WithError(err).Debugf("fqdn %s is no cidr", zone.Fqdn)
		} else {
			if rZoneNet.Contains(ip) {
				_, mask := rZoneNet.Mask.Size()
				networks[mask] = zones[i]
				if mask > maxMask {
					maxMask = mask
				}
			}
		}
	}
	return networks[maxMask]
}

func (p *ProviderConfig) recordSet(ep *endpoint.Endpoint, getObject bool) (recordSet infobloxRecordSet, err error) {
	var ttl uint32
	if ep.RecordTTL.IsConfigured() {
		ttl = uint32(ep.RecordTTL)
	}
	switch ep.RecordType {
	case endpoint.RecordTypeA:
		var res []ibclient.RecordA
		obj := ibclient.NewEmptyRecordA()
		obj.Name = ep.DNSName
		// TODO: get target index
		obj.Ipv4Addr = ep.Targets[0]
		obj.Ttl = ttl
		obj.UseTtl = true
		if getObject {
			queryParams := ibclient.NewQueryParams(false, map[string]string{"name": obj.Name})
			err = p.client.GetObject(obj, "", queryParams, &res)
			if err != nil && !isNotFoundError(err) {
				return
			}
		}
		recordSet = infobloxRecordSet{
			obj: obj,
			res: &res,
		}
	case endpoint.RecordTypePTR:
		var res []ibclient.RecordPTR
		obj := ibclient.NewEmptyRecordPTR()
		obj.PtrdName = ep.DNSName
		// TODO: get target index
		obj.Ipv4Addr = ep.Targets[0]
		obj.Ttl = ttl
		obj.UseTtl = true
		if getObject {
			queryParams := ibclient.NewQueryParams(false, map[string]string{"name": obj.PtrdName})
			err = p.client.GetObject(obj, "", queryParams, &res)
			if err != nil && !isNotFoundError(err) {
				return
			}
		}
		recordSet = infobloxRecordSet{
			obj: obj,
			res: &res,
		}
	case endpoint.RecordTypeCNAME:
		var res []ibclient.RecordCNAME
		obj := ibclient.NewEmptyRecordCNAME()
		obj.Name = ep.DNSName
		obj.Canonical = ep.Targets[0]
		obj.Ttl = ttl
		obj.UseTtl = true
		if getObject {
			queryParams := ibclient.NewQueryParams(false, map[string]string{"name": obj.Name})
			err = p.client.GetObject(obj, "", queryParams, &res)
			if err != nil && !isNotFoundError(err) {
				return
			}
		}
		recordSet = infobloxRecordSet{
			obj: obj,
			res: &res,
		}
	case endpoint.RecordTypeTXT:
		var res []ibclient.RecordTXT
		// The Infoblox API strips enclosing double quotes from TXT records lacking whitespace.
		// Here we reconcile that fact by making this state match that reality.
		if target, err2 := strconv.Unquote(ep.Targets[0]); err2 == nil && !strings.Contains(ep.Targets[0], " ") {
			ep.Targets = endpoint.Targets{target}
		}
		obj := ibclient.NewEmptyRecordTXT()
		obj.Text = ep.Targets[0]
		obj.Name = ep.DNSName
		obj.Ttl = ttl
		obj.UseTtl = true
		// TODO: Zone?
		if getObject {
			queryParams := ibclient.NewQueryParams(false, map[string]string{"name": obj.Name})
			err = p.client.GetObject(obj, "", queryParams, &res)
			if err != nil && !isNotFoundError(err) {
				return
			}
		}
		recordSet = infobloxRecordSet{
			obj: obj,
			res: &res,
		}
	}
	return
}

func (p *ProviderConfig) buildRecord(change *infobloxChange) (*infobloxRecordSet, error) {
	rs, err := p.recordSet(change.Endpoint, !(change.Action == infobloxCreate))
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

func lookupEnvAtoi(key string, fallback int) (i int) {
	val, ok := os.LookupEnv(key)
	if !ok {
		i = fallback
		return
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		i = fallback
		return
	}
	return
}
