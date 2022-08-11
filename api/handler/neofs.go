package handler

import "github.com/nspcc-dev/neofs-sdk-go/eacl"

type Ast struct {
	Resources []*AstResource
}

type NeoFS interface {
	AstToTable(ast *Ast) (*eacl.Table, error)
	TableToAst(table *eacl.Table, bktName string) *Ast
	BucketACLToTable(acp *AccessControlPolicy, resInfo *ResourceInfo) (*eacl.Table, error)
}
