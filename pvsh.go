package npvdkgrs

import (
	"errors"
	"fmt"
	"strings"

	"github.com/alinush/go-mcl"
)

type PVSH struct {
	ID mcl.Fr
	PK mcl.G2
}

func (p PVSH) Encode(sh mcl.Fr, g2 mcl.G2) (string, error) {
	// Algorithm 1
	r := mcl.Fr{}
	r.SetByCSPRNG()

	// Algorithm 2
	var Q mcl.G1
	if err := Q.HashAndMapTo(appendBuffer(p.ID.Serialize(), p.PK.Serialize())); err != nil {
		return "", err
	}

	// Algorithm 3
	var pairingParam mcl.G2
	mcl.G2Mul(&pairingParam, &p.PK, &r)

	var e mcl.GT
	mcl.Pairing(&e, &Q, &pairingParam)

	var eh mcl.Fr
	eh.SetHashOf(e.Serialize())

	e.Clear()

	// Algorithm 4
	var c mcl.Fr
	mcl.FrAdd(&c, &sh, &eh)

	// Algorithm 5
	var U mcl.G2
	mcl.G2Mul(&U, &g2, &r)

	// Algorithm 6
	var H mcl.G1
	err := H.HashAndMapTo(
		[]byte(fmt.Sprintf("%s.%s.%s", Q.GetString(16), c.GetString(16), U.GetString(16))),
	)
	if err != nil {
		return "", err
	}

	// Algorithm 7
	var mulParam mcl.Fr
	mcl.FrDiv(&mulParam, &eh, &r)

	var V mcl.G1
	mcl.G1Mul(&V, &H, &mulParam)

	// Algorithm 8
	result := fmt.Sprintf("%s.%s.%s", c.GetString(16), U.GetString(16), V.GetString(16))

	r.Clear()
	Q.Clear()
	c.Clear()
	U.Clear()
	V.Clear()

	return result, nil
}

func (p PVSH) Verify(ph mcl.G2, esh string, g2 mcl.G2) error {
	// Deserialize necessary values from ESH
	eshArray := strings.Split(esh, ".")
	if len(eshArray) != 3 {
		return errors.New("invalid ESH")
	}

	var c mcl.Fr
	if err := c.SetString(eshArray[0], 16); err != nil {
		return err
	}
	var U mcl.G2
	if err := U.SetString(eshArray[1], 16); err != nil {
		return err
	}
	var V mcl.G1
	if err := V.SetString(eshArray[2], 16); err != nil {
		return err
	}

	// Algorithm 1 // in real implementation Q is an input parameter...
	var Q mcl.G1
	if err := Q.HashAndMapTo(appendBuffer(p.ID.Serialize(), p.PK.Serialize())); err != nil {
		return err
	}

	// Algorithm 2
	var H mcl.G1
	err := H.HashAndMapTo([]byte(fmt.Sprintf("%s.%s.%s", Q.GetString(16), eshArray[0], eshArray[1])))
	if err != nil {
		return err
	}

	// Algorithm 3
	var pairingParam mcl.G2
	mcl.G2Mul(&pairingParam, &g2, &c)

	var e1 mcl.GT
	mcl.Pairing(&e1, &H, &pairingParam)

	var e2Param1 mcl.GT
	mcl.Pairing(&e2Param1, &H, &ph)
	var e2Param2 mcl.GT
	mcl.Pairing(&e2Param2, &V, &U)

	var e2 mcl.GT
	mcl.GTMul(&e2, &e2Param1, &e2Param2)

	// Algorithm 4
	if !e1.IsEqual(&e2) {
		return errors.New("inconsistent (c, U, V)")
	}

	return nil
}

func (p PVSH) Decode(sk mcl.Fr, esh string) (*mcl.Fr, error) {
	eshArray := strings.Split(esh, ".")
	if len(eshArray) != 3 {
		return nil, errors.New("invalid ESH")
	}

	var c mcl.Fr
	if err := c.SetString(eshArray[0], 16); err != nil {
		return nil, err
	}
	var U mcl.G2
	if err := U.SetString(eshArray[1], 16); err != nil {
		return nil, err
	}

	// Algorithm 1
	var Q mcl.G1
	if err := Q.HashAndMapTo(appendBuffer(p.ID.Serialize(), p.PK.Serialize())); err != nil {
		return nil, err
	}

	// Algorithm 2
	var eParam1 mcl.G1
	mcl.G1Mul(&eParam1, &Q, &sk)

	var e mcl.GT
	mcl.Pairing(&e, &eParam1, &U)

	var eh mcl.Fr
	eh.SetHashOf(e.Serialize())

	// Algorithm 3
	var sh mcl.Fr
	mcl.FrSub(&sh, &c, &eh)

	return &sh, nil
}

func appendBuffer(b1 []byte, b2 []byte) []byte {
	var tmp = make([]byte, len(b1)+len(b2))
	tmp = append(tmp, b1...)
	tmp = append(tmp, b2...)
	return tmp
}
