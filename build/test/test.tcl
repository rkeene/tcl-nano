#! /usr/bin/env tclsh

lappend auto_path [file join [file dirname [info script]] .. ..]

package require nano

proc test1 {} {
	# Detached signature
	set data [binary decode hex 0000000000000000000000000000000000000000000000000000000000000000]
	set key  [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set sig  [string toupper [binary encode hex [::nano::internal::signDetached $data $key]]]
	set sig_expected 1C2DE9B8A71215F949A11BBEA7EFA4ECD67A8C2B5A9AD98AE6B1AB7F7A3D2CFD715F570309148C7B39C346FB9B91B321D7E75BD598F271AF31AB60A99D086709

	if {$sig ne $sig_expected} {
		puts "\[FAIL\] Got: $sig"
		puts "\[FAIL\] Exp: $sig_expected"

		return false
	}

	# Public key generation
	set pubKey_expected "FE1934767B26FA05A1526E40101E899959AB088FA1C4219865F33669E8EB99B6"
	set pubKey [::nano::internal::publicKey $key]
	set pubKey [string toupper [binary encode hex $pubKey]]
	if {$pubKey ne $pubKey_expected} {
		puts "\[FAIL\] Got: $pubKey"
		puts "\[FAIL\] Exp: $pubKey_expected"

		return false
	}

	# Detached signature verification
	## Positive
	set data   [binary decode hex 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF]
	set key    [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set pubKey [::nano::internal::publicKey $key]
	set sig    [::nano::internal::signDetached $data $key]
	set verified [::nano::internal::verifyDetached $data $sig $pubKey]
	if {!$verified} {
		puts "\[FAIL\] Got: $verified"
		puts "\[FAIL\] Exp: true"
		return false
	}

	## Negative
	set pubKey [binary decode hex "7E0008FAD05BD9E22A8DEBA963CE3C9C769BC01B00974226D264C9078A7A98A8"]
	set verified [::nano::internal::verifyDetached $data $sig $pubKey]
	if {$verified} {
		puts "\[FAIL\] Got: $verified"
		puts "\[FAIL\] Exp: false"
		return false
	}
}

test1
