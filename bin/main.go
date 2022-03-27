package main

import (
	"fmt"
	"github.com/alinush/go-mcl"
)

func main() {
	mcl.InitMclHelper(mcl.BLS12_381)
	mcl.SetETHserialization(false)

	// init
	fp1 := mcl.Fp{}
	fp1.SetInt64(1)
	fp2 := mcl.Fp{}
	fp2.SetInt64(0)

	tmp := mcl.Fp2{D: [2]mcl.Fp{fp1, fp2}}
	var tmpG2 mcl.G2
	mcl.MapToG2(&tmpG2, &tmp)

	// id
	id := mcl.Fr{}
	id.SetByCSPRNG()

	// sk / pk
	sk := mcl.Fr{}
	sk.SetByCSPRNG()

	var pk mcl.G2
	mcl.G2Mul(&pk, &tmpG2, &sk)

	// sh / ph
	sh := mcl.Fr{}
	sh.SetByCSPRNG()

	var ph mcl.G2
	mcl.G2Mul(&ph, &tmpG2, &sh)

	// const ESH = PVSHEncode(id, PK, sh, g2);
	//	const verificationResult = PVSHVerify(id, PK, PH, ESH, g2);
	//	const decodedSh = PVSHDecode(id, PK, sk, ESH);

	fmt.Println("PK: ", string(pk.GetString(16)))
	fmt.Println("sk: ", string(sk.GetString(16)))
	fmt.Println("PH: ", string(ph.GetString(16)))
	fmt.Println("sh: ", string(sh.GetString(16)))
}
