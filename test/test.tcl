#! /usr/bin/env tclsh

foreach {arg val} $argv {
	switch -exact -- $arg {
		"--libpath" {
			lappend auto_path [file normalize $val]
		}
	}
}

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
	set key [::nano::key::newKey]
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
	set key [::nano::key::fromSeed $seed 0]
	set pubKey [string toupper [binary encode hex [::nano::internal::publicKey $key]]]
	set pubKey_expected "B63EC7A797F2A5858C754EC9C0537920C4F9DEA58F9F411F0C2161F6D303AA7A"
	if {$pubKey ne $pubKey_expected} {
		puts "\[3.FAIL\] Got: $pubKey"
		puts "\[3.FAIL\] Exp: $pubKey_expected"

		return false
	}

	# Generate a new seed
	set seed [::nano::key::newSeed]

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

	set addrCheck [::nano::address::fromPublicKey $pub -nano]
	if {$addrCheck ne $addr} {
		puts "\[2.FAIL\] Got: $addrCheck"
		puts "\[2.FAIL\] Exp: $addr"

		return false
	}

	return true
}

proc test_blocks {} {
	set seed [binary decode hex C4D214F19E706E9C7487CEF00DE8059200C32414F0ED82E5E33B523AEDF719BA]
	set key [::nano::key::fromSeed $seed 0 -hex]
	set address [::nano::address::fromPrivateKey $key -xrb]

	# High-level primitives
	## Receive/Open
	set block [::nano::block::create::receive \
		to $address \
		amount 1000000000000000000000000000000 \
		sourceBlock "207D3043D77B84E892AD4949D147386DE4C2FE4B2C8DC13F9469BC4A764681A7" \
		signKey $key -json true
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
		signKey $key -json true
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
	set blockDict [::nano::block::dict::fromBlock [::nano::block::json::toBlock $block]]
	dict unset blockDict _blockData

	set block     [::nano::block::json::fromDict $blockDict]
	set block     [::nano::block::json::sign $block $key -update]
	set blockDict [::json::json2dict $block]
	set blockSignature [string toupper [dict get $blockDict signature]]
	if {$blockSignature ne $blockSignature_expected} {
		puts "\[3.FAIL\] Got: $blockSignature"
		puts "\[3.FAIL\] Exp: $blockSignature_expected"

		return false
	}

	# Verifying a block
	set signature [::nano::block::json::sign $block $key -hex]
	set verify    [::nano::block::json::verifySignature $block]
	if {!$verify} {
		puts "\[4.FAIL\] Got: $verify"
		puts "\[4.FAIL\] Exp: true"

		return false
	}

	# JSON Parse an old-style block
	## Parsing
	set block [::nano::block::dict::fromJSON {
		{
			"account"     : "xrb_13ezf4od79h1tgj9aiu4djzcmmguendtjfuhwfukhuucboua8cpoihmh8byo",
			"destination" : "xrb_1gys8r4crpxhp94n4uho5cshaho81na6454qni5gu9n53gksoyy1wcd4udyb",
			"type"        : "send",
			"previous"    : "F685856D73A488894F7F3A62BC3A88E17E985F9969629FF3FDD4A0D4FD823F24",
			"work"        : "efe5bf06a43d0e0a",
			"signature"   : "E373A1A38C9A239F4D2AAE52B40EF6DFC8BFEDCEB476588958073B7F462746854282FFE4B98FA6782E92798DAD0E5483C3356550A31339E1D7934B487EF4570D",
			"balance"     : "00F035A9C7D818E7C34148C524FFFFEE"
		}
	}]

	## Ensure the balance was converted
	set balance [dict get $block "balance"]
	set balance_expected "1247239665165579623600346831066759150"
	if {$balance != $balance_expected} {
		puts "\[5.FAIL\] Got: $balance"
		puts "\[5.FAIL\] Exp: $balance_expected"

		return false
	}

	## Convert to JSON
	set block [::nano::block::json::fromDict $block]

	## Ensure balance is in hex again
	set balance [dict get [::json::json2dict $block] "balance"]
	set balance_expected "00F035A9C7D818E7C34148C524FFFFEE"
	if {$balance != $balance_expected} {
		puts "\[6.FAIL\] Got: $balance"
		puts "\[6.FAIL\] Exp: $balance_expected"

		return false
	}

	## Convert back and verify signature
	set verify [::nano::block::json::verifySignature $block]
	if {!$verify} {
		puts "\[7.FAIL\] Got: $verify"
		puts "\[7.FAIL\] Exp: true"

		return false
	}

	## Verify Proof of Work
	set verify [::nano::block::json::validateWork $block]
	if {!$verify} {
		puts "\[8.FAIL\] Got: $verify"
		puts "\[8.FAIL\] Exp: true"

		return false
	}

	# A typical block cycle
	set seed FC11FC93CA62BEB6F39290D476798757CE9A767E6CF598AE2F9D0976944736A8
	set key [::nano::key::fromSeed $seed]
	set account [::nano::address::fromPrivateKey $key]
	set frontierHash $seed
	::nano::account::setFrontier $account $frontierHash 1 $account
	set block [::nano::account::send $account $account 1 $key]
	set block [::nano::block::json::work $block -update]
	set block [::nano::block::json::filter $block]
	set block [::nano::block::dict::fromJSON $block]
	set signature [dict get $block "signature"]
	set signature_expected "5A3B477463080E11E7CB9FAEE5A900BEC93D33A0679F76FC6FC2F29211D0AF5C8421D0DFC3744FFDAD21F29FA0203B8007594B9DDCF70921B63EA66712963D0A"
	if {$signature ne $signature_expected} {
		puts "\[9.FAIL\] Got: $signature"
		puts "\[9.FAIL\] Exp: $signature_expected"

		return false
	}

	set verify [::nano::block::dict::validateWork $block]
	if {!$verify} {
		puts "\[10.FAIL\] Got: $verify"
		puts "\[10.FAIL\] Exp: true"

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
	set workData  "1C840FED01000000D8CBCF440CB1E4DF386761E6E66609563BD62A649DF6D0BE"
	set work      [::nano::work::fromWorkData $workData]
	set verify    [::nano::work::validate $workData $work]
	if {!$verify} {
		puts "\[3.FAIL\] Got: $verify"
		puts "\[3.FAIL\] Exp: true"

		return false
	}

	return true
}

proc test_balances {} {
	set balance 1001500000000000000000000000000
	set balance [::nano::balance::toUnit $balance Nano 3]
	set balance_expected "1.001"
	if {$balance != $balance_expected} {
		puts "\[1.FAIL\] Got: $balance"
		puts "\[1.FAIL\] Exp: $balance_expected"

		return false
	}

	set balance 1001510000000000000000000000000
	set balance [::nano::balance::toUnit $balance Nano 3]
	set balance_expected "1.002"
	if {$balance != $balance_expected} {
		puts "\[2.FAIL\] Got: $balance"
		puts "\[2.FAIL\] Exp: $balance_expected"

		return false
	}

	set balance 100150000000000000000000000000000000000
	set balance [::nano::balance::toUnit $balance unano 3]
	set balance_expected "100150000000000000000.000"
	if {$balance != $balance_expected} {
		puts "\[3.FAIL\] Got: $balance"
		puts "\[3.FAIL\] Exp: $balance_expected"

		return false
	}
	set balance 10
	set balance [::nano::balance::toRaw $balance Nano]
	set balance_expected 10000000000000000000000000000000
	if {$balance != $balance_expected} {
		puts "\[4.FAIL\] Got: $balance"
		puts "\[4.FAIL\] Exp: $balance_expected"

		return false
	}

	set balance 1.000000000000000000001
	set balance [::nano::balance::toRaw $balance Nano]
	set balance_expected 1000000000000000000001000000000
	if {$balance != $balance_expected} {
		puts "\[5.FAIL\] Got: $balance"
		puts "\[5.FAIL\] Exp: $balance_expected"

		return false
	}

	set unitName [::nano::balance::normalizeUnitName Mnano]
	set unitName_expected "Nano"
	if {$unitName != $unitName_expected} {
		puts "\[6.FAIL\] Got: $unitName"
		puts "\[6.FAIL\] Exp: $unitName_expected"

		return false
	}

	set balance 3.3346
	set balance [::nano::balance::toRaw $balance unano]
	set balance_expected $balance
	set balance [::nano::balance::toHuman $balance]
	set balance [::nano::balance::toRaw {*}$balance]
	if {$balance != $balance_expected} {
		puts ""
		puts "\[7.FAIL\] Got: $balance"
		puts "\[7.FAIL\] Exp: $balance_expected"

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
	balances
}

foreach test $tests {
	puts -nonewline "\[    \] $test"
	flush stdout

	if {[catch {
		if {![test_$test]} {
			puts "\r\[FAIL\] $test"
			exit 1
		} else {
			puts "\r\[ OK \] $test"
		}
	} testErr]} {
		puts "\r\[ERR!\] $test: $testErr"
		exit 1
	}
}

puts "\[DONE\] All tests pass"

exit 0
