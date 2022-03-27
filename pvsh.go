package npvdkgrs

import (
	"fmt"
	"github.com/alinush/go-mcl"
)

func Encode(id mcl.Fr, pk mcl.G2, sh mcl.Fr, g2 mcl.G2) string {
	// Algorithm 1
	r := mcl.Fr{}
	r.SetByCSPRNG()

	// Algorithm 2
	var Q mcl.G1 // TODO

	// Algorithm 3
	var pairingParam mcl.G2
	mcl.G2Mul(&pairingParam, &pk, &r)

	var e mcl.GT
	mcl.Pairing(&e, &Q, &pairingParam)

	var eh mcl.Fr // TODO

	e.Clear()

	// Algorithm 4
	var c mcl.Fr
	mcl.FrAdd(&c, &sh, &eh)

	// Algorithm 5
	var U mcl.G2
	mcl.G2Mul(&U, &g2, &r)

	// Algorithm 6
	var H mcl.G1 // TODO

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

	return result
}
