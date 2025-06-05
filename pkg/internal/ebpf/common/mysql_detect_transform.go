package ebpfcommon

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/sqlprune"
)

const (
	MySQLResponseStatusOK  = 0
	MySQLResponseStatusErr = 1
)

type mySQLRequestsCacheKey struct {
	sourcePort uint16
	pid        uint32
	ns         uint32
}

var mySQLRequestsCache = expirable.NewLRU[mySQLRequestsCacheKey, MySQLRequestEvent](2048, nil, 3*time.Minute) // TODO(matt): configurable?

func ReadMySQLEventIntoSpan(eventType byte, record *ringbuf.Record) (request.Span, bool, error) {
	switch eventType {
	case EventTypeMySQLRequest:
		requestEvent, err := ReinterpretCast[MySQLRequestEvent](record.RawSample)
		if err != nil {
			return request.Span{}, true, err
		}

		handleMysqlRequest(requestEvent)

		return request.Span{}, true, err
	case EventTypeMySQLResponse:
		responseEvent, err := ReinterpretCast[MySQLResponseEvent](record.RawSample)
		if err != nil {
			return request.Span{}, true, err
		}

		span, err := handleMysqlResponse(responseEvent)
		if err != nil {
			return request.Span{}, true, err
		}

		return span, false, nil
	default:
		return request.Span{}, true, fmt.Errorf("unknown MySQL event type: %d", eventType)
	}
}

func handleMysqlRequest(event *MySQLRequestEvent) {
	mySQLRequestsCache.Add(mySQLRequestsCacheKey{
		sourcePort: event.ConnInfo.S_port,
		pid:        event.Pid.HostPid,
		ns:         event.Pid.Ns,
	}, *event)
}

func handleMysqlResponse(event *MySQLResponseEvent) (request.Span, error) {
	key := mySQLRequestsCacheKey{
		sourcePort: event.ConnInfo.S_port,
		pid:        event.Pid.HostPid,
		ns:         event.Pid.Ns,
	}

	requestEvent, ok := mySQLRequestsCache.Get(key)
	if !ok {
		return request.Span{}, errors.New("no matching MySQL request found for response")
	}

	span := newMySQLSpan(&requestEvent, event)
	mySQLRequestsCache.Remove(key)

	return span, nil
}

func mysqlCommandIDToString(commandID uint8) string {
	switch commandID {
	case 0x3:
		return "QUERY"
	// TODO(matt): prepared statements
	// case 0x16:
	// 	return "STMT_PREPARE"
	// case 0x17:
	// 	return "STMT_EXECUTE"
	default:
		return ""
	}
}

func newMySQLSpan(requestEvent *MySQLRequestEvent, responseEvent *MySQLResponseEvent) request.Span {
	var (
		peer, hostname, statement string
		status                    int
		sqlError                  *request.SQLError
	)

	if requestEvent.ConnInfo.S_port != 0 || requestEvent.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&requestEvent.ConnInfo)).reqHostInfo()
	}

	statement = unix.ByteSliceToString(requestEvent.Buf[:requestEvent.QueryLen])
	op, tables := sqlprune.SQLParseOperationAndTableNEW(statement)

	if responseEvent.ResponseStatus == MySQLResponseStatusErr {
		status = 1
		sqlError = &request.SQLError{
			Code:     responseEvent.Err.ErrorCode,
			SQLState: unix.ByteSliceToString(responseEvent.Err.SqlState[:]),
			Message:  unix.ByteSliceToString(responseEvent.Err.ErrorMessage[:]),
		}
	}

	return request.Span{
		Type:         request.EventTypeSQLClient,
		Start:        int64(requestEvent.StartMonotimeNs),
		RequestStart: int64(requestEvent.StartMonotimeNs),
		End:          int64(responseEvent.EndMonotimeNs),
		Pid: request.PidInfo{
			HostPID:   requestEvent.Pid.HostPid,
			UserPID:   requestEvent.Pid.UserPid,
			Namespace: requestEvent.Pid.Ns,
		},
		Peer:         peer,
		PeerPort:     int(requestEvent.ConnInfo.S_port),
		Host:         hostname,
		HostPort:     int(requestEvent.ConnInfo.D_port),
		Statement:    statement,
		SubType:      int(request.DBMySQL),
		Method:       op,
		Path:         tables,
		Status:       status,
		SQLCommand:   mysqlCommandIDToString(requestEvent.CommandId),
		SQLError:     sqlError,
		TraceID:      trace.TraceID(requestEvent.Tp.TraceId),
		SpanID:       trace.SpanID(requestEvent.Tp.SpanId),
		ParentSpanID: trace.SpanID(requestEvent.Tp.ParentId),
		Flags:        requestEvent.Tp.Flags,
	}
}
