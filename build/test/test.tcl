#! /usr/bin/env tclsh

lappend auto_path [file normalize [lindex $argv 0]]

package require nano

proc test_selftest {} {
	::nano::internal::selfTest
	return true
}

proc test_signatures {} {
	# Detached signature
	set data [binary decode hex 0000000000000000000000000000000000000000000000000000000000000000]
	set key  [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set sig  [string toupper [binary encode hex [::nano::internal::signDetached $data $key]]]
	set sig_expected 1C2DE9B8A71215F949A11BBEA7EFA4ECD67A8C2B5A9AD98AE6B1AB7F7A3D2CFD715F570309148C7B39C346FB9B91B321D7E75BD598F271AF31AB60A99D086709

	if {$sig ne $sig_expected} {
		puts "\[1.FAIL\] Got: $sig"
		puts "\[1.FAIL\] Exp: $sig_expected"

		return false
	}

	# Public key generation
	set pubKey_expected "FE1934767B26FA05A1526E40101E899959AB088FA1C4219865F33669E8EB99B6"
	set pubKey [::nano::internal::publicKey $key]
	set pubKey [string toupper [binary encode hex $pubKey]]
	if {$pubKey ne $pubKey_expected} {
		puts "\[2.FAIL\] Got: $pubKey"
		puts "\[2.FAIL\] Exp: $pubKey_expected"

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
		puts "\[3.FAIL\] Got: $verified"
		puts "\[3.FAIL\] Exp: true"
		return false
	}

	## Negative
	set pubKey [binary decode hex "7E0008FAD05BD9E22A8DEBA963CE3C9C769BC01B00974226D264C9078A7A98A8"]
	set verified [::nano::internal::verifyDetached $data $sig $pubKey]
	if {$verified} {
		puts "\[4.FAIL\] Got: $verified"
		puts "\[4.FAIL\] Exp: false"
		return false
	}

	return true
}

proc test_hashing {} {
	# Basic test
	set data [binary decode hex 4451686437A2BF5C4759100DE2ADE0F39B6877275AF997906B71B1A8EF1550A2]
	set hash [binary encode hex [::nano::internal::hashData $data]]
	set hash_expected "84ac733547d71c312e707508646008a9d8f84f7093e60ca91e4eb376365ac1921fdde6e8ccb3875ea12369d9f6fb02237f51f4c05f3555e57d11800deda7319f"
	if {$hash ne $hash_expected} {
		puts "\[1.FAIL\] Got: $hash"
		puts "\[1.FAIL\] Exp: $hash_expected"

		return false
	}

	# Reduced size test
	set data [binary decode hex 4451686437A2BF5C4759100DE2ADE0F39B6877275AF997906B71B1A8EF1550A2]
	set hash [binary encode hex [::nano::internal::hashData $data 32]]
	set hash_expected "863d40311043ad24e56034de73fb0b77a9f13fbac37ea61368509839ba1832e2"
	if {$hash ne $hash_expected} {
		puts "\[2.FAIL\] Got: $hash"
		puts "\[2.FAIL\] Exp: $hash_expected"

		return false
	}

	return true
}

proc test_keygeneration {} {
	# Generate a new key pair
	set key [::nano::key::generateNewKey]
	if {[string length $key] != 32} {
		puts "\[1.FAIL\] Got: [string length $key]"
		puts "\[1.FAIL\] Exp: 32"

		return false
	}

	# Generate a public key from the private key
	set data   [binary decode hex 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF]
	set pubKey [::nano::internal::publicKey $key]
	set sig    [::nano::internal::signDetached $data $key]
	set verified [::nano::internal::verifyDetached $data $sig $pubKey]
	if {!$verified} {
		puts "\[2.FAIL\] Got: $verified"
		puts "\[2.FAIL\] Exp: true"

		return false
	}

	# Create a key pair from a seed and index
	set seed [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set key [::nano::key::computeKey $seed 0]
	set pubKey [string toupper [binary encode hex [::nano::internal::publicKey $key]]]
	set pubKey_expected "B63EC7A797F2A5858C754EC9C0537920C4F9DEA58F9F411F0C2161F6D303AA7A"
	if {$pubKey ne $pubKey_expected} {
		puts "\[3.FAIL\] Got: $pubKey"
		puts "\[3.FAIL\] Exp: $pubKey_expected"

		return false
	}

	return true
}

proc test_addressformat {} {
	set addr nano_35ynhw4qd1pam88azf86nk8ka5sthnzaubcw5fawingep1sjydwaiw8xy7t6
	set pub  8FD47F057582C8998C8FB4C4A48D240F3A7D3E8DA55C1B51C851CCB0331F2F88

	set pubCheck [string toupper [::nano::address::toPublicKey $addr -hex -verify]]
	if {$pubCheck ne $pub} {
		puts "\[1.FAIL\] Got: $pubCheck"
		puts "\[1.FAIL\] Exp: $pub"

		return false
	}

	set addrCheck [::nano::address::fromPublicKey $pub]
	if {$addrCheck ne $addr} {
		puts "\[2.FAIL\] Got: $addrCheck"
		puts "\[2.FAIL\] Exp: $addr"

		return false
	}

	return true
}

proc test_blocks {} {
	set seed [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set key [::nano::key::computeKey $seed 0 -hex]
	set address [::nano::address::fromPrivateKey $key -xrb]

	# High-level primitives
	## Receive/Open
	set block [::nano::block::create::receive \
		to $address \
		amount 1000000000000000000000000000000 \
		sourceBlock "207D3043D77B84E892AD4949D147386DE4C2FE4B2C8DC13F9469BC4A764681A7" \
		signKey $key
	]

	set blockDict [::json::json2dict $block]
	set blockSignature [string toupper [dict get $blockDict signature]]
	set blockSignature_expected "B574DE37F5FFF3DCFB5D0E505FC36B402444777CAA99BA86F89E9B82B6EB901B809554287F0B67D8C2A8306B4F69FE77FD0C9B3D0D10422A02CFEBB3810C7D02"
	if {$blockSignature ne $blockSignature_expected} {
		puts "\[1.FAIL\] Got: $blockSignature"
		puts "\[1.FAIL\] Exp: $blockSignature_expected"

		return false
	}

	## Send
	set block [::nano::block::create::send \
		from $address \
		to "xrb_1unc5hriitrdjq5dnyhr3zmd8t5hm7rhm9a1u3uun5ycbaacpu649yh5c4b5" \
		previous "D46BFC2E35B5A3CA4230839D67676F4A8498C2567F571D2B66A7F7B72214DEEE" \
		previousBalance 1000000000000000000000000000000 \
		amount 1000000000000000000000000000000 \
		signKey $key
	]

	set blockDict [::json::json2dict $block]
	set blockSignature [string toupper [dict get $blockDict signature]]
	set blockSignature_expected "BFE238A27FFBFBCF722EDC3700CA8E2405F5AE18E353E591917A2CBE393F0759C948E710DD723B3BFB21B491D9D0856EEFCAC0E25C7E5FF06185FE5D633B5204"
	if {$blockSignature ne $blockSignature_expected} {
		puts "\[2.FAIL\] Got: $blockSignature"
		puts "\[2.FAIL\] Exp: $blockSignature_expected"

		return false
	}

	# JSON Parsing a block
	set blockDict [::nano::block::toDict [::nano::block::fromJSON $block]]
	dict unset blockDict _blockData
	dict set blockDict signKey $key

	set block     [::nano::block::jsonFromDict $blockDict]
	set blockDict [::json::json2dict $block]
	set blockSignature [string toupper [dict get $blockDict signature]]
	if {$blockSignature ne $blockSignature_expected} {
		puts "\[3.FAIL\] Got: $blockSignature"
		puts "\[3.FAIL\] Exp: $blockSignature_expected"

		return false
	}

	# Verifying a block
	set signature [::nano::block::signBlockJSON $block $key -hex]
	set verify    [::nano::block::verifyBlockJSON $block $signature [::nano::key::publicKeyFromPrivateKey $key]]
	if {!$verify} {
		puts "\[4.FAIL\] Got: $verify"
		puts "\[4.FAIL\] Exp: true"

		return false
	}

	return true
}

proc test_work {} {
	# Verification
	## Positive
	set blockhash "0CF7F1E71B6C692BD8CBCF440CB1E4DF386761E6E66609563BD62A649DF6D0BE"
	set work      "01A87EEC1B6C692B"
	set verify [::nano::work::validate $blockhash $work]
	if {!$verify} {
		puts "\[1.FAIL\] Got: $verify"
		puts "\[1.FAIL\] Exp: true"

		return false
	}

	## Negative
	set work      "11A87EEC1B6C692B"
	set verify [::nano::work::validate $blockhash $work]
	if {$verify} {
		puts "\[2.FAIL\] Got: $verify"
		puts "\[2.FAIL\] Exp: false"

		return false
	}

	# Generation
	set blockhash "1C840FED01000000D8CBCF440CB1E4DF386761E6E66609563BD62A649DF6D0BE"
	set work      [::nano::work::fromBlockhash $blockhash]
	set verify    [::nano::work::validate $blockhash $work]
	if {!$verify} {
		puts "\[3.FAIL\] Got: $verify"
		puts "\[3.FAIL\] Exp: true"

		return false
	}

	return true
}

set tests {
	selftest
	signatures
	hashing
	keygeneration
	addressformat
	blocks
	work
}

foreach test $tests {
	if {![test_$test]} {
		puts "FAILED test $test"
		exit 1
	} else {
		puts "\[OK\] $test"
	}
}

puts "DONE"

exit 0
