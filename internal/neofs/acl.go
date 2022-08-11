package neofs

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type orderedAstResource struct {
	Index    int
	Resource *handler.AstResource
}

const (
	serviceRecordResourceKey    = "Resource"
	serviceRecordGroupLengthKey = "GroupLength"
)

type serviceRecord struct {
	Resource           string
	GroupRecordsLength int
}

func (s serviceRecord) ToEACLRecord() *eacl.Record {
	serviceRecord := eacl.NewRecord()
	serviceRecord.SetAction(eacl.ActionAllow)
	serviceRecord.SetOperation(eacl.OperationGet)
	serviceRecord.AddFilter(eacl.HeaderFromService, eacl.MatchUnknown, serviceRecordResourceKey, s.Resource)
	serviceRecord.AddFilter(eacl.HeaderFromService, eacl.MatchUnknown, serviceRecordGroupLengthKey, strconv.Itoa(s.GroupRecordsLength))
	eacl.AddFormedTarget(serviceRecord, eacl.RoleSystem)
	return serviceRecord
}

func formRecords(resource *handler.AstResource) ([]*eacl.Record, error) {
	var res []*eacl.Record

	for i := len(resource.Operations) - 1; i >= 0; i-- {
		astOp := resource.Operations[i]
		record := eacl.NewRecord()
		record.SetOperation(astOp.Op)
		record.SetAction(astOp.Action)
		if astOp.IsGroupGrantee() {
			eacl.AddFormedTarget(record, eacl.RoleOthers)
		} else {
			targetKeys := make([]ecdsa.PublicKey, 0, len(astOp.Users))
			for _, user := range astOp.Users {
				pk, err := keys.NewPublicKeyFromString(user)
				if err != nil {
					return nil, fmt.Errorf("public key from string: %w", err)
				}
				targetKeys = append(targetKeys, (ecdsa.PublicKey)(*pk))
			}
			// Unknown role is used, because it is ignored when keys are set
			eacl.AddFormedTarget(record, eacl.RoleUnknown, targetKeys...)
		}
		if len(resource.Object) != 0 {
			if len(resource.Version) != 0 {
				var id oid.ID
				if err := id.DecodeString(resource.Version); err != nil {
					return nil, fmt.Errorf("parse object version (oid): %w", err)
				}
				record.AddObjectIDFilter(eacl.MatchStringEqual, id)
			} else {
				record.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, resource.Object)
			}
		}
		res = append(res, record)
	}

	return res, nil
}

func formReverseOrderResources(resourceMap map[string]orderedAstResource) []*handler.AstResource {
	orderedResources := make([]orderedAstResource, 0, len(resourceMap))
	for _, resource := range resourceMap {
		orderedResources = append(orderedResources, resource)
	}
	sort.Slice(orderedResources, func(i, j int) bool {
		return orderedResources[i].Index >= orderedResources[j].Index // reverse order
	})

	result := make([]*handler.AstResource, len(orderedResources))
	for i, ordered := range orderedResources {
		res := ordered.Resource
		for j, k := 0, len(res.Operations)-1; j < k; j, k = j+1, k-1 {
			res.Operations[j], res.Operations[k] = res.Operations[k], res.Operations[j]
		}

		result[i] = res
	}

	return result
}

func addOperationsAndUpdateMap(orderedRes orderedAstResource, record eacl.Record, resMap map[string]orderedAstResource) {
	for _, target := range record.Targets() {
		orderedRes.Resource.Operations = addToList(orderedRes.Resource.Operations, record, target)
	}
	resMap[orderedRes.Resource.Name()] = orderedRes
}

func getResourceOrCreate(resMap map[string]orderedAstResource, index int, resInfo handler.ResourceInfo) orderedAstResource {
	resource, ok := resMap[resInfo.Name()]
	if !ok {
		resource = orderedAstResource{
			Index:    index,
			Resource: &handler.AstResource{ResourceInfo: resInfo},
		}
	}
	return resource
}

func resInfoFromFilters(bucketName string, filters []eacl.Filter) handler.ResourceInfo {
	resInfo := handler.ResourceInfo{Bucket: bucketName}
	for _, filter := range filters {
		if filter.Matcher() == eacl.MatchStringEqual {
			if filter.Key() == object.AttributeFileName {
				resInfo.Object = filter.Value()
			} else if filter.Key() == v2acl.FilterObjectID {
				resInfo.Version = filter.Value()
			}
		}
	}

	return resInfo
}

func tryServiceRecord(record eacl.Record) *serviceRecord {
	if record.Action() != eacl.ActionAllow || record.Operation() != eacl.OperationGet ||
		len(record.Targets()) != 1 || len(record.Filters()) != 2 {
		return nil
	}

	target := record.Targets()[0]
	if target.Role() != eacl.RoleSystem {
		return nil
	}

	resourceFilter := record.Filters()[0]
	recordsFilter := record.Filters()[1]
	if resourceFilter.From() != eacl.HeaderFromService || recordsFilter.From() != eacl.HeaderFromService ||
		resourceFilter.Matcher() != eacl.MatchUnknown || recordsFilter.Matcher() != eacl.MatchUnknown ||
		resourceFilter.Key() != serviceRecordResourceKey || recordsFilter.Key() != serviceRecordGroupLengthKey {
		return nil
	}

	groupLength, err := strconv.Atoi(recordsFilter.Value())
	if err != nil {
		return nil
	}

	return &serviceRecord{
		Resource:           resourceFilter.Value(),
		GroupRecordsLength: groupLength,
	}
}

func addToList(operations []*handler.AstOperation, rec eacl.Record, target eacl.Target) []*handler.AstOperation {
	var (
		found       *handler.AstOperation
		groupTarget = target.Role() == eacl.RoleOthers
	)

	for _, astOp := range operations {
		if astOp.Op == rec.Operation() && astOp.IsGroupGrantee() == groupTarget {
			found = astOp
		}
	}

	if found != nil {
		if !groupTarget {
			for _, key := range target.BinaryKeys() {
				found.Users = append(found.Users, hex.EncodeToString(key))
			}
		}
	} else {
		astOperation := &handler.AstOperation{
			Op:     rec.Operation(),
			Action: rec.Action(),
		}
		if !groupTarget {
			for _, key := range target.BinaryKeys() {
				astOperation.Users = append(astOperation.Users, hex.EncodeToString(key))
			}
		}

		operations = append(operations, astOperation)
	}

	return operations
}

type getRecordFunc func(op eacl.Operation) *eacl.Record

func getRecordFunction(grantee *handler.Grantee) (getRecordFunc, error) {
	switch grantee.Type {
	case handler.AcpAmazonCustomerByEmail:
	case handler.AcpCanonicalUser:
		pk, err := keys.NewPublicKeyFromString(grantee.ID)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse canonical ID %s: %w", grantee.ID, err)
		}
		return func(op eacl.Operation) *eacl.Record {
			return getAllowRecord(op, pk)
		}, nil
	case handler.AcpGroup:
		return func(op eacl.Operation) *eacl.Record {
			return getOthersRecord(op, eacl.ActionAllow)
		}, nil
	}
	return nil, fmt.Errorf("unknown type: %s", grantee.Type)
}

func isValidGrant(grant *handler.Grant) bool {
	return (grant.Permission == handler.ACLFullControl || grant.Permission == handler.ACLRead || grant.Permission == handler.ACLWrite) &&
		(grant.Grantee.Type == handler.AcpCanonicalUser || (grant.Grantee.Type == handler.AcpGroup && grant.Grantee.URI == handler.AllUsersGroup))
}

func permissionToOperations(permission handler.AWSACL) []eacl.Operation {
	switch permission {
	case handler.ACLFullControl:
		return handler.FullOps
	case handler.ACLRead:
		return handler.ReadOps
	case handler.ACLWrite:
		return handler.WriteOps
	}
	return nil
}

func getAllowRecord(op eacl.Operation, pk *keys.PublicKey) *eacl.Record {
	record := eacl.NewRecord()
	record.SetOperation(op)
	record.SetAction(eacl.ActionAllow)
	// Unknown role is used, because it is ignored when keys are set
	eacl.AddFormedTarget(record, eacl.RoleUnknown, (ecdsa.PublicKey)(*pk))
	return record
}

func getOthersRecord(op eacl.Operation, action eacl.Action) *eacl.Record {
	record := eacl.NewRecord()
	record.SetOperation(op)
	record.SetAction(action)
	eacl.AddFormedTarget(record, eacl.RoleOthers)
	return record
}
