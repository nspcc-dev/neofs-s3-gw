package auth

import (
	"fmt"
	"testing"
)

func TestName(t *testing.T) {
	//target:= "AWS4-HMAC-SHA256 Credential=vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJM0HrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB/20210809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2811ccb9e242f41426738fb1fa6a456ef37c63505da1a160f3d76a4f51b17581"
	target := "AWS4-HMAC-SHA256 Credential=badauth/20210809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2811ccb9e242f41426738fb1fa6a456ef37c63505da1a160f3d76a4f51b17581"

	subMatcher := &regexpSubmatcher{re: authorizationFieldRegexp}

	submatches := subMatcher.getSubmatches(target)
	fmt.Println(submatches)
}
