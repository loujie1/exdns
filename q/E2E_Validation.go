package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

var (
	errNoDNSKEY               = errors.New("no DNSKEY records found")
	errMissingKSK             = errors.New("no KSK DNSKEY found for DS records")
	errFailedToConvertKSK     = errors.New("failed to convert KSK DNSKEY record to DS record")
	errMismatchingDS          = errors.New("KSK DNSKEY record does not match DS record from parent zone")
	errNoSignatures           = errors.New("no RRSIG records for zone that should be signed")
	errMissingDNSKEY          = errors.New("no matching DNSKEY found for RRSIG records")
	errInvalidSignaturePeriod = errors.New("incorrect signature validity period")
	errMissingSigned          = errors.New("signed records are missing")

	localIPaddrs []net.IP
)

const (
	rootzone = "."
)

func E2eValidation(qname string, msg *dns.Msg, rootkeys []dns.RR) bool {
	rrsets := make(map[string][]dns.RR)
	childMap := make(map[string]string)
	DSwithSig := make(map[string][]dns.RR)
	for _, rr := range msg.Extra {
		name := rr.Header().Name
		switch rr.Header().Rrtype {
		case dns.TypeDS:
			DSwithSig[name] = append(DSwithSig[name], rr)
		case dns.TypeRRSIG:
			sig := rr.(*dns.RRSIG)
			if sig.TypeCovered == dns.TypeDS {
				DSwithSig[name] = append(DSwithSig[name], rr)
				childMap[sig.SignerName] = name
			} else {
				rrsets[name] = append(rrsets[rr.Header().Name], rr)
			}
		default:
			rrsets[name] = append(rrsets[rr.Header().Name], rr)
		}
	}

	fmt.Printf("----------------E2E VALIDATION START------------\n")

	var parentDSRR []dns.RR
	currzone := rootzone
	keys := make(map[uint16]*dns.DNSKEY)

	for {
		fmt.Printf("\nStart Checking Zone :%s\n", currzone)
		rrset := rrsets[currzone]

		// append DS for child zone
		child, isParent := childMap[currzone]
		if isParent {
			rrset = append(rrset, DSwithSig[child]...)
		}

		fmt.Printf("----------------Zone Sections for: %s ------------\n", currzone)
		for _, r := range rrset {
			fmt.Printf("%s\n", r.String())
		}
		fmt.Printf("-------------------------------------------------------\n")
		// get keys
		keys = make(map[uint16]*dns.DNSKEY)
		for _, a := range rrset {
			if a.Header().Rrtype == dns.TypeDNSKEY {
				dnskey := a.(*dns.DNSKEY)
				tag := dnskey.KeyTag()
				if dnskey.Flags == 256 || dnskey.Flags == 257 {
					keys[tag] = dnskey
				}
			}
		}

		// verify keys
		if currzone == rootzone {
			dsset := []dns.RR{}
			for _, a := range rootkeys {
				if dnskey, ok := a.(*dns.DNSKEY); ok {
					dsset = append(dsset, dnskey.ToDS(dns.RSASHA1))
				}
			}
			if len(dsset) == 0 {
				fmt.Printf(";- Root Zone DS set empty")
				return false
			}

			if _, err := verifyDS(keys, dsset); err != nil {
				fmt.Printf(";- Root Zone DS not Verified, err: %s\n", err.Error())
				return false
			} else {
				fmt.Printf(";+ Root Zone DS Verified")
			}

		} else {
			if len(parentDSRR) == 0 {
				fmt.Printf(";? DS for %s not found\n", currzone)
				return false
			}
			if unsupportedDigest, err := verifyDS(keys, parentDSRR); err != nil {
				fmt.Printf(";- DNSSEC DS verify failed, signer: %s, error: %s, unsupported digest: %t", currzone, err.Error(), unsupportedDigest)
				return false
			} else {
				fmt.Printf(";- KSK verified with DS record for domain %s\n", currzone)
			}
		}

		if !SigCheck(rrset, keys) {
			return false
		}
		if isParent {
			parentDSRR = extractRRSet(rrset, "", dns.TypeDS)
			currzone = child
		} else {
			// no DS, so this is the last zone
			fmt.Printf(";+ the authoritative zone for answer: %s \n", currzone)
			break
		}
	}
	fmt.Printf("----------------Start Checking Answer Section------------\n")
	if !SigCheck(msg.Answer, keys) {
		return false
	}
	fmt.Printf("----------------Start Checking NS Section------------\n")
	if !SigCheck(msg.Ns, keys) {
		return false
	}
	fmt.Printf("----------------E2E VALIDATION END------------\n")
	return true
}

func verifyDS(keyMap map[uint16]*dns.DNSKEY, parentDSSet []dns.RR) (bool, error) {
	unsupportedDigest := false
	for i, r := range parentDSSet {
		parentDS, ok := r.(*dns.DS)
		if !ok {
			continue
		}

		if parentDS.DigestType == dns.GOST94 {
			unsupportedDigest = true
		}

		ksk, present := keyMap[parentDS.KeyTag]
		if !present {
			continue
		}
		//TODO: miek dns lib doesn't support GOST 34.11 currently
		ds := ksk.ToDS(parentDS.DigestType)
		if ds == nil {
			if i != len(parentDSSet)-1 {
				continue
			}
			return unsupportedDigest, errFailedToConvertKSK
		}
		if ds.Digest != parentDS.Digest {
			if i != len(parentDSSet)-1 {
				continue
			}
			return unsupportedDigest, errMismatchingDS
		}
		return unsupportedDigest, nil
	}

	return unsupportedDigest, errMissingKSK
}
func extractRRSet(in []dns.RR, name string, t ...uint16) []dns.RR {
	out := []dns.RR{}
	tMap := make(map[uint16]struct{}, len(t))
	for _, t := range t {
		tMap[t] = struct{}{}
	}
	for _, r := range in {
		if _, ok := tMap[r.Header().Rrtype]; ok {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

func SigCheck(set []dns.RR, keyMap map[uint16]*dns.DNSKEY) bool {
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			key := keyMap[rr.(*dns.RRSIG).KeyTag]
			if key == nil {
				fmt.Printf(";? DNSKEY %s/%d not found\n", rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag)
				return false
				continue
			}
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf(";- Bogus signature, %s does not validate (DNSKEY %s/%d) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), err.Error(), expired)
				return false
			} else {
				fmt.Printf(";+ Secure signature, %s validates (DNSKEY %s/%d) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), expired)
			}
		}
	}
	return true
}
