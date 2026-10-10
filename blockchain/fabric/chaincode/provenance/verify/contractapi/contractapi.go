package contractapi

import "errors"

type Timestamp struct {
	Seconds int64
	Nanos   int32
}

type StateQueryIteratorInterface interface {
	HasNext() bool
	Next() (*KV, error)
	Close() error
}
type KV struct {
	Key   string
	Value []byte
}

type ChaincodeStubInterface interface {
	GetState(string) ([]byte, error)
	PutState(string, []byte) error
	GetTxID() string
	GetChannelID() string
	GetTxTimestamp() (*Timestamp, error)
	CreateCompositeKey(string, []string) (string, error)
	SplitCompositeKey(string) (string, []string, error)
	GetStateByPartialCompositeKey(string, []string) (StateQueryIteratorInterface, error)
	GetStateByRange(string, string) (StateQueryIteratorInterface, error)
	SetEvent(string, []byte) error
}
type ClientIdentityInterface interface{ GetMSPID() (string, error) }
type TransactionContextInterface interface {
	GetStub() ChaincodeStubInterface
	GetClientIdentity() ClientIdentityInterface
}
type Contract struct{}
type chaincode struct{}

func (c *chaincode) Start() error                     { return nil }
func NewChaincode(...interface{}) (*chaincode, error) { return &chaincode{}, errors.New("stub") }
