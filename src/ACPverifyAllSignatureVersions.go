package main

// 20241230 temporarily disabled signature verification to reduce binary size
//
//import (
//	"fmt"
//	"github.com/avast/apkverifier"
//	"os"
//)
//
//func verifyApk(apkpath string) bool {
//	// Read configuration
//	res, err := apkverifier.Verify(apkpath, nil)
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "Verification failed: %s\n", err.Error())
//		return false
//	}
//	// Determine whether it is V1
//	if res.SigningSchemeId == 1 {
//		fmt.Printf("Verification scheme used: v%d signature, Janus vulnerability present!\n", res.SigningSchemeId)
//	} else {
//		fmt.Printf("Verification scheme used: v%d signature, no Janus vulnerability!\n", res.SigningSchemeId)
//	}
//	// Output trust information
//	cert, _ := apkverifier.PickBestApkCert(res.SignerCerts)
//	if cert == nil {
//		fmt.Printf("No certificate found.\n")
//	} else {
//		fmt.Println(cert)
//	}
//
//	return true
//}
