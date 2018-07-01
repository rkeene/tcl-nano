#! /usr/bin/env tclsh

lappend auto_path [file join [file dirname [info script]] .. ..]

package require nano

proc test1 {} {
	set data [binary decode hex 0000000000000000000000000000000000000000000000000000000000000000]
	set key  [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set signed [string toupper [binary encode hex [::nano::internal::signDetached $data $key]]]
	set signed_expected 1C2DE9B8A71215F949A11BBEA7EFA4ECD67A8C2B5A9AD98AE6B1AB7F7A3D2CFD715F570309148C7B39C346FB9B91B321D7E75BD598F271AF31AB60A99D086709

	if {$signed ne $signed_expected} {
		puts "\[FAIL\] Got: $signed"
		puts "\[FAIL\] Exp: $signed_expected"
		return false
	}

	set pubKey [::nano::internal::publicKey $key]
	set pubKey [binary encode hex $pubKey]

	puts "Pub: $pubKey"
}

test1
