package trie

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

var emptyCodeHash = crypto.Keccak256(nil)

// SliceIterator wraps the nodeIterator object
// to allow the Trie Slice API
type SliceIterator struct {
	nodeIterator
}

// NewSliceIterator returns a SliceIterator object
func (st *SecureTrie) NewSliceIterator(start []byte) *SliceIterator {
	if st.trie.Hash() == emptyState {
		return &SliceIterator{}
	}
	it := &SliceIterator{}
	it.trie = &st.trie
	it.err = it.seek(start)
	return it
}

// Slice walks down the given depth from the starting path
// defined at the SliceIterator construction.
func (it *SliceIterator) Slice(maxDepth int, includeBlobs bool) ([][]common.Hash, [][][]byte) {
	keys := make([][]common.Hash, maxDepth+1)
	for i, _ := range keys {
		// group nodes by their depth
		keys[i] = make([]common.Hash, 0)
	}

	var blobs [][][]byte
	if includeBlobs {
		blobs = make([][][]byte, maxDepth+1)
		for i, _ := range blobs {
			blobs[i] = make([][]byte, 0)
		}
	}

	// correct the max depth to the current length of the stack
	maxDepth = maxDepth + len(it.stack)

	// boundary conditions and depth variables
	// don't worry, the code is extensively documented
	headCheckPoint := false
	var headDepth, currentDepth, indexDepth int

	for {
		// prevent the iterator to go deeper than the maxDepth
		if len(it.stack) == maxDepth+1 {
			it.pop()
		}

		// update the state of the iterator
		it.Next(true)

		// the stack (path from root to the slice head) is including the latter
		currentDepth = len(it.stack) - 1

		// set the checkpoint
		if !headCheckPoint {
			headDepth = currentDepth
			headCheckPoint = true
		} else {
			if currentDepth <= headDepth {
				// we are back to head level, the traversal is complete
				// for example, we started at depth 3, we would go
				// 000, 0001, 00012, 00013, 00021, 00022.
				// at 001 we call it in, since we finished the traversal
				break
			}
		}

		// add the found key
		indexDepth = currentDepth - headDepth
		if (it.Hash() == common.Hash{}) {
			// we are storing the pointer to the next one,
			// then, if we are in a leaf we already stored it
			continue
		}

		keys[indexDepth] = append(keys[indexDepth], it.Hash())
		if includeBlobs {
			blobs[indexDepth] = append(blobs[indexDepth], it.Blob(it.Hash()))
		}
	}

	return keys, blobs
}

// StemKeys returns the keys of the stem of the slice.
// The stem is the path from the root of the trie to the head of the slice.
// This path is already stored in memory from the trie construction,
// hence it should be faster to retrieve than the actual blobs.
func (it *SliceIterator) StemKeys() []common.Hash {
	if len(it.stack) == 0 {
		return nil
	}

	output := make([]common.Hash, 0)

	for _, item := range it.stack[:len(it.stack)-1] {
		output = append(output, item.hash)
	}

	return output
}

// StemBlobs returns the blobs of the stem of the slice.
// The stem is the path from the root of the trie to the head of the slice.
func (it *SliceIterator) StemBlobs() [][]byte {
	if len(it.stack) == 0 {
		return nil
	}

	output := make([][]byte, 0)

	for _, item := range it.stack[:len(it.stack)-1] {
		output = append(output, it.Blob(item.hash))
	}

	return output
}

// seek is an overload of the nodeIterator.seek() function
// to allow for odd paths
func (it *SliceIterator) seek(prefix []byte) error {
	// Move forward until we're just before the closest match to key.
	for {
		state, parentIndex, path, err := it.peek(bytes.HasPrefix(prefix, it.path))
		if err == errIteratorEnd {
			return errIteratorEnd
		} else if err != nil {
			return seekError{prefix, err}
		} else if bytes.Compare(path, prefix) >= 0 {
			return nil
		}
		it.push(state, parentIndex, path)
	}
}

// Blob will try to get from the cache these blobs,
// defaulting to the persistent database in case of failure.
func (it *SliceIterator) Blob(hash common.Hash) []byte {
	db := it.trie.db

	// TODO
	// hacer un cache de slices
	// ver si esta aca, sacar

	db.lock.RLock()
	node := db.nodes[hash]
	db.lock.RUnlock()

	if node != nil {
		return node.rlp()
	}

	// content unavailable in memory, attempt to retrieve from disk
	blob, err := db.diskdb.Get(hash[:])
	if err != nil || blob == nil {
		return nil
	}

	return blob
}

// GetLeavesInfo originally called GetLeavesNumberAndSmartContractStorageRoots
// returns the number of leaves, smart contracts, the latter paths
// (we won't fetch preimages) and their storage roots, to save the user a traversal
//
// NOTE
// This function is not designed with a max traversal depth
func (it *SliceIterator) GetLeavesInfo() (numberOfLeaves, numberOfSmartContracts int, storageRoots [][2][]byte, evmCodes []string) {
	storageRoots = make([][2][]byte, 0)
	evmCodes = make([]string, 0)

	// traverse the slice
	headCheckPoint := false
	var headDepth, currentDepth int

	for {
		// update the state of the iterator
		it.Next(true)

		// the stack (path from root to the slice head) is including the latter
		currentDepth = len(it.stack) - 1

		// set the checkpoint
		if !headCheckPoint {
			headDepth = currentDepth
			headCheckPoint = true
		} else {
			if currentDepth <= headDepth {
				// we are back to head level, the traversal is complete
				// for example, we started at depth 3, we would go
				// 000, 0001, 00012, 00013, 00021, 00022.
				// at 001 we call it in, since we finished the traversal
				break
			}
		}

		// on leaf, we identify whether is a smart contract
		if it.Leaf() {
			hash := it.stack[len(it.stack)-2].hash
			path := hexToKeybytes(it.Path())

			leafType, root, evmCode := it.identifyLeafType(it.Blob(hash))

			if leafType == "smart contract" {
				numberOfSmartContracts++

				// get the paths and storage roots
				pair := [2][]byte{
					path,
					root[:],
				}
				storageRoots = append(storageRoots, pair)
				evmCodes = append(evmCodes, evmCode) // TODO hacer mejor esta wea
			}

			numberOfLeaves++
		}
	}

	return
}

type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte
}

// identifyLeafType is a convenience method
// if the leaf is a smart contract, it will return the storage root
func (it *SliceIterator) identifyLeafType(input []byte) (string, common.Hash, string) {
	var i []interface{}
	var account Account

	err := rlp.DecodeBytes(input, &i)
	if err != nil {
		// this is a debugging function, we want it to break
		// the program if it's not a leaf
		panic(err)
	}

	switch len(i) {
	case 2:
		first := i[0].([]byte)
		last := i[1].([]byte)

		switch first[0] / 16 {
		case '\x00':
			fallthrough
		case '\x01':

			panic("extension")
		case '\x02':
			fallthrough
		case '\x03':
			err = rlp.DecodeBytes(last, &account)
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(account.CodeHash, emptyCodeHash) {
				// TODO
				// devolver tambien el codigo del smart contract
				// como se hace?
				// - el CodeHash es una key en la levelDB, tengo que pedirlo
				// - db.diskdb.Get(hash[:])
				return "smart contract", account.Root, fmt.Sprintf("%x", it.Blob(common.BytesToHash(account.CodeHash[:])))
			} else {
				return "balance account", common.Hash{}, ""
			}
		default:
			panic("unknown hex prefix on trie node")
		}

	case 17:
		panic("branch")

	default:
		panic("unknown trie node type")
	}
}
