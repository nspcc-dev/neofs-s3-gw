package layer

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/minio/minio/neofs/pool"
	"github.com/nspcc-dev/neofs-api-go/object"
	"github.com/nspcc-dev/neofs-api-go/query"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-api-go/storagegroup"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	dataChunkSize = 3 * object.UnitsMB
	objectVersion = 1
)

type (
	putParams struct {
		addr        refs.Address
		name        string
		size        int64
		r           io.Reader
		userHeaders map[string]string
	}

	sgParams struct {
		addr    refs.Address
		objects []refs.ObjectID
	}

	delParams struct {
		addr refs.Address
	}

	getParams struct {
		addr   refs.Address
		start  int64
		length int64
		writer io.Writer
	}
)

// objectSearchContainer returns all available objects in the container.
func (n *layer) objectSearchContainer(ctx context.Context, cid refs.CID) ([]refs.ObjectID, error) {
	var q query.Query
	q.Filters = append(q.Filters, query.Filter{
		Type: query.Filter_Exact,
		Name: object.KeyRootObject,
	})

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	queryBinary, err := q.Marshal()
	if err != nil {
		return nil, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: refs.Address{CID: cid},
		Verb: service.Token_Info_Search,
	})
	if err != nil {
		return nil, err
	}

	req := new(object.SearchRequest)
	req.Query = queryBinary
	req.QueryVersion = 1
	req.ContainerID = cid
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	searchClient, err := object.NewServiceClient(conn).Search(ctx, req)
	if err != nil {
		return nil, err
	}

	var (
		response []refs.Address
		result   []refs.ObjectID
	)

	for {
		resp, err := searchClient.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, errors.New("search command received error")
		}

		response = append(response, resp.Addresses...)
	}

	for i := range response {
		result = append(result, response[i].ObjectID)
	}

	return result, nil
}

// objectFindID returns object id (uuid) based on it's nice name in s3. If
// nice name is uuid compatible, then function returns it.
func (n *layer) objectFindID(ctx context.Context, cid refs.CID, name string, put bool) (refs.ObjectID, error) {
	var (
		id refs.ObjectID
		q  query.Query
	)

	q.Filters = append(q.Filters, query.Filter{
		Type: query.Filter_Exact,
		Name: object.KeyRootObject,
	})
	q.Filters = append(q.Filters, query.Filter{
		Type:  query.Filter_Exact,
		Name:  AWS3NameHeader,
		Value: name,
	})

	queryBinary, err := q.Marshal()
	if err != nil {
		return id, err
	}

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return id, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: refs.Address{CID: cid},
		Verb: service.Token_Info_Search,
	})
	if err != nil {
		return id, err
	}

	req := new(object.SearchRequest)
	req.Query = queryBinary
	req.QueryVersion = 1
	req.ContainerID = cid
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return id, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	searchClient, err := object.NewServiceClient(conn).Search(ctx, req)
	if err != nil {
		return id, err
	}

	var response []refs.Address

	for {
		resp, err := searchClient.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}

			return id, errors.New("search command received error")
		}

		response = append(response, resp.Addresses...)
	}

	switch ln := len(response); {
	case ln > 1:
		return id, errors.New("several objects with the same name found")
	case ln == 1:
		return response[0].ObjectID, nil
	default:
		// Minio lists all objects with and without nice names. All objects
		// without nice name still have "name" in terms of minio - uuid encoded
		// into string. There is a tricky case when user upload object
		// with nice name that is encoded uuid.
		// There is an optimisation to parse name and return uuid if it name is uuid
		// compatible. It _should not_ work in case of put operation, because object
		// with uuid compatible nice name may not exist. Therefore this optimization
		// breaks object put logic and must be turned off.
		if !put {
			err := id.Parse(name)
			if err == nil {
				return id, nil
			}
		}
		return id, errors.New("object not found")
	}
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, addr refs.Address) (*object.Object, error) {

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: addr,
		Verb: service.Token_Info_Head,
	})
	if err != nil {
		return nil, err
	}

	req := new(object.HeadRequest)
	req.Address = addr
	req.FullHeaders = true
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := object.NewServiceClient(conn).Head(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.Object, nil
}

// objectGet and write it into provided io.Reader.
func (n *layer) objectGet(ctx context.Context, p getParams) (*object.Object, error) {
	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: p.addr,
		Verb: service.Token_Info_Get,
	})
	if err != nil {
		return nil, err
	}

	// todo: replace object.Get() call by object.GetRange() for
	//       true sequential reading support; it will be possible when
	//       object.GetRange() response message become gRPC stream.
	req := new(object.GetRequest)
	req.Address = p.addr
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	getClient, err := object.NewServiceClient(conn).Get(ctx, req)
	if err != nil {
		return nil, err
	}

	var (
		headerReceived bool

		buf       = new(bytes.Buffer)
		objHeader = new(object.Object)
	)

	for {
		resp, err := getClient.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		if !headerReceived {
			objHeader = resp.GetObject()

			_, hdr := objHeader.LastHeader(object.HeaderType(object.TombstoneHdr))
			if hdr != nil {
				return nil, errors.New("object already removed")
			}

			_, err = buf.Write(objHeader.Payload)
			if err != nil && err != io.EOF {
				return nil, err
			}

			headerReceived = true

			continue
		}

		chunk := resp.GetChunk()

		_, err = buf.Write(chunk)
		if err != nil && err != io.EOF {
			return nil, err
		}
	}

	buf = bytes.NewBuffer(buf.Bytes()[p.start : p.start+p.length])
	_, err = io.Copy(p.writer, buf)

	return objHeader, err
}

// objectPut into neofs, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, p putParams) (*object.Object, error) {
	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: p.addr,
		Verb: service.Token_Info_Put,
	})
	if err != nil {
		n.log.Error("could not prepare token",
			zap.Error(err))
		return nil, err
	}

	putClient, err := object.NewServiceClient(conn).Put(ctx)
	if err != nil {
		n.log.Error("could not prepare PutClient",
			zap.Error(err))
		return nil, err
	}

	if p.userHeaders == nil {
		p.userHeaders = make(map[string]string)
	}

	p.userHeaders[AWS3NameHeader] = p.name

	readBuffer := make([]byte, dataChunkSize)
	obj := &object.Object{
		SystemHeader: object.SystemHeader{
			Version:       objectVersion,
			ID:            p.addr.ObjectID,
			OwnerID:       n.uid,
			CID:           p.addr.CID,
			PayloadLength: uint64(p.size),
		},
		Headers: parseUserHeaders(p.userHeaders),
	}

	req := object.MakePutRequestHeader(obj)
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		n.log.Error("could not prepare request",
			zap.Error(err))
		return nil, err
	}

	err = putClient.Send(req)
	if err != nil {
		n.log.Error("could not send request",
			zap.Error(err))
		return nil, err
	}

	read, err := p.r.Read(readBuffer)
	for read > 0 {
		if err != nil && err != io.EOF {
			n.log.Error("something went wrong",
				zap.Error(err))
			return nil, err
		}

		if read > 0 {
			req := object.MakePutRequestChunk(readBuffer[:read])
			req.SetTTL(service.SingleForwardingTTL)
			// req.SetBearer(bearerToken)

			err = service.SignRequestData(n.key, req)
			if err != nil {
				n.log.Error("could not sign chunk request",
					zap.Error(err))
				return nil, err
			}

			err = putClient.Send(req)
			if err != nil && err != io.EOF {
				n.log.Error("could not send chunk",
					zap.Error(err))
				return nil, err
			}
		}

		read, err = p.r.Read(readBuffer)
	}

	_, err = putClient.CloseAndRecv()
	if err != nil {
		n.log.Error("could not finish request",
			zap.Error(err))
		return nil, err
	}

	// maybe make a head?
	return obj, nil
}

// storageGroupPut prepares storage group object and put it into neofs.
func (n *layer) storageGroupPut(ctx context.Context, p sgParams) (*object.Object, error) {
	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: p.addr,
		Verb: service.Token_Info_Put,
	})
	if err != nil {
		return nil, err
	}

	client := object.NewServiceClient(conn)
	// todo: think about timeout
	putClient, err := client.Put(ctx)
	if err != nil {
		return nil, err
	}

	sg := &object.Object{
		SystemHeader: object.SystemHeader{
			Version: objectVersion,
			ID:      p.addr.ObjectID,
			OwnerID: n.uid,
			CID:     p.addr.CID,
		},
		Headers: make([]object.Header, 0, len(p.objects)),
	}

	for i := range p.objects {
		sg.AddHeader(&object.Header{Value: &object.Header_Link{
			Link: &object.Link{Type: object.Link_StorageGroup, ID: p.objects[i]},
		}})
	}

	sg.SetStorageGroup(new(storagegroup.StorageGroup))

	req := object.MakePutRequestHeader(sg)
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return nil, err
	}

	err = putClient.Send(req)
	if err != nil {
		return nil, err
	}

	_, err = putClient.CloseAndRecv()
	if err != nil {
		return nil, err
	}

	return sg, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, p delParams) error {
	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: p.addr,
		Verb: service.Token_Info_Delete,
	})
	if err != nil {
		return err
	}

	req := new(object.DeleteRequest)
	req.Address = p.addr
	req.OwnerID = n.uid
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)
	// req.SetBearer(bearerToken)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err = object.NewServiceClient(conn).Delete(ctx, req)

	return err
}
