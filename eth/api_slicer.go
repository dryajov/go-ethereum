package eth

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

////////////////////////////////////////////////////////////////////////////////
//
// GetSlice response structures
//
////////////////////////////////////////////////////////////////////////////////

type GetSliceResponse struct {
	SliceID   string                             `json:"slice-id"`
	MetaData  GetSliceResponseMetadata           `json:"metadata"`
	TrieNodes GetSliceResponseTrieNodes          `json:"trie-nodes"`
	Leaves    map[string]GetSliceResponseAccount `json:"leaves"` // we won't be using addresses, but keccak256(address)
}

type GetSliceResponseMetadata struct {
	TimeStats map[string]string `json:"time-ms"`    // stem, state, storage (one by one)
	NodeStats map[string]string `json:"trie-nodes"` // total, leaves, smart contracts
}

type GetSliceResponseTrieNodes struct {
	Stem       map[string]string `json:"stem"`
	Head       map[string]string `json:"head"`
	SliceNodes map[string]string `json:"slice-nodes"`
}

type GetSliceResponseAccount struct {
	StorageRoot string `json:"storage-root"`
	EVMCode     string `json:"evm-code"`
}

// GetSlice retrieves a slice from the state, alongside its stem.
//
// Parameters
// - path 			path from root where the slice starts
// - depth			depth to walk from the slice head
// - stateRoot		state root of the GetSliceResponse
// - onlyKeys		omit the blobs in the response
func (api *PublicDebugAPI) GetSlice(ctx context.Context, path string, depth int, stateRoot string, storage bool) (GetSliceResponse, error) {
	var timerStart int64

	// check the path parameter
	slicePath := pathStringToKeyBytes(path)
	if slicePath == nil {
		return GetSliceResponse{},
			fmt.Errorf("incorrect input, expected string representation of hex for path")
	}

	// check the depth parameter
	// TODO
	// should be positive (non-zero)

	// check the stateRoot parameter
	stateRootByte, err := hexutil.Decode(stateRoot)
	if err != nil {
		return GetSliceResponse{},
			fmt.Errorf("incorrect input, expected string representation of hex for root")
	}

	// prepare the response object
	response := GetSliceResponse{
		SliceID: fmt.Sprintf("%s-%02d-%s", path, depth, stateRoot[2:]),
		MetaData: GetSliceResponseMetadata{
			TimeStats: make(map[string]string),
			NodeStats: make(map[string]string),
		},
		TrieNodes: GetSliceResponseTrieNodes{
			Stem:       make(map[string]string),
			Head:       make(map[string]string),
			SliceNodes: make(map[string]string),
		},
		Leaves: make(map[string]GetSliceResponseAccount),
	}

	// load a trie with the given state root
	timerStart = time.Now().UnixNano()
	tr, err := api.eth.BlockChain().GetSecureTrie(common.BytesToHash(stateRootByte))
	if err != nil {
		return GetSliceResponse{}, fmt.Errorf("error loading the trie %v", err)
	}

	response.addTimer("00 trie-loading", timerStart)

	// prepare to fetch the stem
	timerStart = time.Now().UnixNano()
	it := tr.NewSliceIterator(slicePath)
	it.Next(true)
	// the actual fetching
	stemKeys := it.StemKeys()
	stemBlobs := it.StemBlobs()
	response.addTimer("01 fetch-stem-keys", timerStart)

	// fill the stem data into the response
	var keyStr string
	for idx, key := range stemKeys {
		keyStr = fmt.Sprintf("%x", key)

		response.TrieNodes.Stem[keyStr] = fmt.Sprintf("%x", stemBlobs[idx])
	}
	response.MetaData.NodeStats["N00 stem-and-head-nodes"] = fmt.Sprintf("%d", len(stemKeys)+1)

	// fetch the slice
	timerStart = time.Now().UnixNano()
	it = tr.NewSliceIterator(slicePath)
	sliceKeys, sliceBlobs := it.Slice(depth, true)
	response.addTimer("02 fetch-slice-keys", timerStart)

	if len(sliceKeys[0]) < 1 || len(sliceBlobs[0]) < 1 {
		return response, nil
	}

	// fill the head field into the response
	response.TrieNodes.Head[fmt.Sprintf("%x", sliceKeys[0][0])] = fmt.Sprintf("%x", sliceBlobs[0][0])

	// fill the rest of the slice data into the response
	for dl, depthLevel := range sliceKeys {
		if dl == 0 {
			// we already delivered the head
			continue
		}

		if len(depthLevel) == 0 {
			// we are done before reaching maxDepth
			response.MetaData.NodeStats["N01 max-depth"] = fmt.Sprintf("%d", dl)
			break
		}

		// remember that we make a separate golang slice per depth level
		// but we return (here in the RPC) everything in a single level.
		// it is the job of the client to assemble back the data
		for k, key := range depthLevel {
			response.TrieNodes.SliceNodes[fmt.Sprintf("%x", key)] = fmt.Sprintf("%x", sliceBlobs[dl][k])
		}

		response.MetaData.NodeStats["N02 total-trie-nodes"] = fmt.Sprintf("%d", len(response.TrieNodes.SliceNodes))
	}

	if storage == true {
		return response, nil
	}

	// TODO
	// we need to add the smart contract code (when it applies)

	// fetch the leaves information
	timerStart = time.Now().UnixNano()
	it = tr.NewSliceIterator(slicePath)
	numberOfLeaves, numberOfSmartContracts, storageRoots, evmCodes := it.GetLeavesInfo()
	response.addTimer("03 fetch-leaves-info", timerStart)

	// fill the leaves info
	response.MetaData.NodeStats["N03 leaves"] = fmt.Sprintf("%d", numberOfLeaves)
	response.MetaData.NodeStats["N04 smart-contacts"] = fmt.Sprintf("%d", numberOfSmartContracts)

	var storagePath, storageRoot string
	for idx, pair := range storageRoots {
		storagePath = fmt.Sprintf("%x", pair[0])
		storageRoot = fmt.Sprintf("%x", pair[1])

		response.Leaves[storagePath] = GetSliceResponseAccount{
			StorageRoot: storageRoot,
			EVMCode:     evmCodes[idx], // TODO este codigo es horrible
		}
	}

	// we are done here
	return response, nil
}

func pathStringToKeyBytes(input string) []byte {
	if input == "" {
		return nil
	}

	// first we convert each character to its hex counterpart
	output := make([]byte, 0)
	var b byte
	for _, c := range input {
		switch {
		case '0' <= c && c <= '9':
			b = byte(c - '0')
		case 'a' <= c && c <= 'f':
			b = byte(c - 'a' + 10)
		default:
			return nil
		}

		output = append(output, b)
	}

	return output
}

func (response *GetSliceResponse) addTimer(key string, timerStart int64) {
	response.MetaData.TimeStats[key] =
		fmt.Sprintf("%.6f", float64(time.Now().UnixNano()-timerStart)/(1000*1000))
}
