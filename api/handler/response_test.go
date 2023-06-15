package handler

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessControlPolicyXML(t *testing.T) {
	// slightly modified (all possible fields are set) sample of AWS S3 ACL from
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
	const policyXML = `
<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>Owner-canonical-user-ID</ID>
    <DisplayName>display-name</DisplayName>
  </Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>Owner-canonical-user-ID</ID>
        <DisplayName>owner-display-name</DisplayName>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>user1-canonical-user-ID</ID>
        <DisplayName>user1-display-name</DisplayName>
      </Grantee>
      <Permission>WRITE</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>user2-canonical-user-ID</ID>
        <DisplayName>user2-display-name</DisplayName>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI> 
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
        <URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI>
      </Grantee>
      <Permission>WRITE</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="AmazonCustomerByEmail">
        <EmailAddress>Grantees@email.com</EmailAddress>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>
`

	var p AccessControlPolicy

	err := xml.Unmarshal([]byte(policyXML), &p)
	require.NoError(t, err)

	require.Equal(t, Owner{
		ID:          "Owner-canonical-user-ID",
		DisplayName: "display-name",
	}, p.Owner)

	require.Len(t, p.AccessControlList, 6)

	g := p.AccessControlList[0]

	require.Equal(t, awsPermFullControl, g.Permission)
	require.Equal(t, "owner-display-name", g.Grantee.DisplayName)
	require.Empty(t, g.Grantee.EmailAddress)
	require.Equal(t, "Owner-canonical-user-ID", g.Grantee.ID)
	require.EqualValues(t, "CanonicalUser", g.Grantee.Type)
	require.Empty(t, g.Grantee.URI)

	g = p.AccessControlList[1]

	require.Equal(t, awsPermWrite, g.Permission)
	require.Equal(t, "user1-display-name", g.Grantee.DisplayName)
	require.Empty(t, g.Grantee.EmailAddress)
	require.Equal(t, "user1-canonical-user-ID", g.Grantee.ID)
	require.EqualValues(t, "CanonicalUser", g.Grantee.Type)
	require.Empty(t, g.Grantee.URI)

	g = p.AccessControlList[2]

	require.Equal(t, awsPermRead, g.Permission)
	require.Equal(t, "user2-display-name", g.Grantee.DisplayName)
	require.Empty(t, g.Grantee.EmailAddress)
	require.Equal(t, "user2-canonical-user-ID", g.Grantee.ID)
	require.EqualValues(t, "CanonicalUser", g.Grantee.Type)
	require.Empty(t, g.Grantee.URI)

	g = p.AccessControlList[3]

	require.Equal(t, awsPermRead, g.Permission)
	require.Empty(t, g.Grantee.DisplayName)
	require.Empty(t, g.Grantee.EmailAddress)
	require.Empty(t, g.Grantee.ID)
	require.EqualValues(t, "Group", g.Grantee.Type)
	require.Equal(t, "http://acs.amazonaws.com/groups/global/AllUsers", g.Grantee.URI)

	g = p.AccessControlList[4]

	require.Equal(t, awsPermWrite, g.Permission)
	require.Empty(t, g.Grantee.DisplayName)
	require.Empty(t, g.Grantee.EmailAddress)
	require.Empty(t, g.Grantee.ID)
	require.EqualValues(t, "Group", g.Grantee.Type)
	require.Equal(t, "http://acs.amazonaws.com/groups/s3/LogDelivery", g.Grantee.URI)

	g = p.AccessControlList[5]

	require.Equal(t, awsPermRead, g.Permission)
	require.Empty(t, g.Grantee.DisplayName)
	require.Equal(t, "Grantees@email.com", g.Grantee.EmailAddress)
	require.Empty(t, g.Grantee.ID)
	require.EqualValues(t, "AmazonCustomerByEmail", g.Grantee.Type)
	require.Empty(t, g.Grantee.URI)

	b, err := xml.Marshal(p)
	require.NoError(t, err)

	var p2 AccessControlPolicy

	err = xml.Unmarshal(b, &p2)
	require.NoError(t, err)

	require.Equal(t, p, p2)
}
