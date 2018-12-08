#! /usr/bin/env tclsh

package require Tcl 8.6.4

package require json
package require json::write

namespace eval ::nano {}
namespace eval ::nano::address {}
namespace eval ::nano::key {}
namespace eval ::nano::block {}
namespace eval ::nano::block::json {}
namespace eval ::nano::block::dict {}
namespace eval ::nano::block::create {}
namespace eval ::nano::work {}
namespace eval ::nano::account {}
namespace eval ::nano::node {}
namespace eval ::nano::ledger {}
namespace eval ::nano::ledger::lmdb {}
namespace eval ::nano::rpc {}
namespace eval ::nano::rpc::client {}
namespace eval ::nano::balance {}
namespace eval ::nano::node::bootstrap {}
namespace eval ::nano::node::realtime {}
namespace eval ::nano::node::cli {}
namespace eval ::nano::network::client {}
namespace eval ::nano::network::server {}
namespace eval ::nano::protocol::create {}
namespace eval ::nano::protocol::parse {}
namespace eval ::nano::protocol::extensions {}
namespace eval ::nano::network::_dns {}

# Constants
set ::nano::block::genesis(main) {{
	"type": "open",
	"source": "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA",
	"representative": "xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
	"account": "xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
	"work": "62f05417dd3fb691",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
}}
set ::nano::block::genesis(beta) {{
	"type": "open",
	"source": "A59A47CC4F593E75AE9AD653FDA9358E2F7898D9ACC8C60E80D0495CE20FBA9F",
	"representative": "xrb_3betaz86ypbygpqbookmzpnmd5jhh4efmd8arr9a3n4bdmj1zgnzad7xpmfp",
	"account": "xrb_3betaz86ypbygpqbookmzpnmd5jhh4efmd8arr9a3n4bdmj1zgnzad7xpmfp",
	"work": "000000000f0aaeeb",
	"signature": "A726490E3325E4FA59C1C900D5B6EEBB15FE13D99F49D475B93F0AACC5635929A0614CF3892764A04D1C6732A0D716FFEB254D4154C6F544D11E6630F201450B"
}}
set ::nano::block::stateBlockPreamble [binary decode hex "0000000000000000000000000000000000000000000000000000000000000006"]
set ::nano::block::zero "0000000000000000000000000000000000000000000000000000000000000000"
set ::nano::balance::zero "00000000000000000000000000000000"
set ::nano::address::zero $::nano::block::zero
set ::nano::address::base32alphabet {13456789abcdefghijkmnopqrstuwxyz}
set ::nano::network::messageTypes {
	"invalid"
	"not_a_type"
	"keepalive"
	"publish"
	"confirm_req"
	"confirm_ack"
	"bulk_pull"
	"bulk_push"
	"frontier_req"
	"bulk_pull_blocks"
	"node_id_handshake"
	"bulk_pull_account"
}
set ::nano::balance::_conversion {
	GNano 1000000000000000000000000000000000000000
	MNano 1000000000000000000000000000000000000
	Gnano 1000000000000000000000000000000000
	Gxrb  1000000000000000000000000000000000
	KNano 1000000000000000000000000000000000
	Nano  1000000000000000000000000000000
	_USER 1000000000000000000000000000000
	NANO  1000000000000000000000000000000
	Mnano 1000000000000000000000000000000
	Mxrb  1000000000000000000000000000000
	Mrai  1000000000000000000000000000000
	knano 1000000000000000000000000000
	kxrb  1000000000000000000000000000
	mNano 1000000000000000000000000000
	nano  1000000000000000000000000
	xrb   1000000000000000000000000
	uNano 1000000000000000000000000
	mnano 1000000000000000000000
	mxrb  1000000000000000000000
	unano 1000000000000000000
	uxrb  1000000000000000000
	Traw  1000000000000
	Graw  1000000000
	Mraw  1000000
	Kraw  1000
	raw   1
}
set ::nano::protocol::extensions {
	node_id_handshake {
		query 1
		response 2
	}
	bulk_pull {
		count_present 1
	}
}

# Address management functions
proc ::nano::address::toPublicKey {address args} {
	set performChecksumCheck false
	set outputFormat "bytes"
	foreach arg $args {
		switch -exact -- $arg {
			"-verify" {
				set performChecksumCheck true
			}
			"-no-verify" {
				set performChecksumCheck false
			}
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	switch -glob -- $address {
		"xrb_*" - "nano_*" {}
		default {
			return -code error "Invalid address (format, header)"
		}
	}

	set address [join [lrange [split $address _] 1 end] _]
	set address [split $address ""]
	if {[llength $address] != 60} {
		return -code error "Invalid address (length)"
	}

	set alphabet [split $::nano::address::base32alphabet ""]
	set result 0
	foreach byte $address {
		set fiveBits [lsearch -exact $alphabet $byte]
		if {$fiveBits < 0} {
			return -code error "Invalid address (format, alphabet)"
		}

		set result [expr {($result << 5) | $fiveBits}]
	}

	set checksum [expr {$result & 0xffffffffff}]
	set result   [expr {$result >> 40}]
	set result   [format %064llX $result]

	if {$performChecksumCheck} {
		set resultBinary [binary decode hex $result]
		set checksumVerify [binary encode hex [string reverse [::nano::internal::hashData $resultBinary 5]]]
		set checksumVerify [expr "0x$checksumVerify"]

		if {$checksum != $checksumVerify} {
			return -code error "Invalid address (checksum)"
		}
	}

	if {$outputFormat eq "bytes"} {
		if {![info exists resultBinary]} {
			set resultBinary [binary decode hex $result]
		}

		set result $resultBinary
	}

	return $result
}

proc ::nano::address::fromPublicKey {publicKey args} {
	set addressPrefix "nano_"
	foreach arg $args {
		switch -exact -- $arg {
			"-xrb" {
				set addressPrefix "xrb_"
			}
			"-nano" {
				set addressPrefix "nano_"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	if {[string length $publicKey] != $::nano::key::publicKeyLength} {
		set publicKey [binary decode hex $publicKey]
	}

	set checksum [string reverse [::nano::internal::hashData $publicKey 5]]
	append publicKey $checksum

	set publicKey [binary encode hex $publicKey]
	set publicKey [expr "0x$publicKey"]
	set alphabet [split $::nano::address::base32alphabet ""]
	set address ""
	for {set index 0} {$index < 60} {incr index} {
		set fiveBits [expr {$publicKey & 0x1F}]
		set publicKey [expr {$publicKey >> 5}]
		set byte [lindex $alphabet $fiveBits]
		append address $byte
	}
	set address [string reverse $address]
	set address "${addressPrefix}${address}"

	return $address
}

proc ::nano::address::fromPrivateKey {privateKey args} {
	set pubKey [::nano::key::publicKeyFromPrivateKey $privateKey]
	tailcall ::nano::address::fromPublicKey $pubKey {*}$args
}

# Key management functions
proc ::nano::key::newSeed {args} {
	set outputFormat "bytes"
	foreach arg $args {
		switch -exact -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set retval [::nano::internal::generateSeed]

	if {$outputFormat eq "hex"} {
		set retval [binary encode hex $retval]
	}

	return $retval
}

proc ::nano::key::newKey {args} {
	set outputFormat "bytes"
	foreach arg $args {
		switch -exact -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set retval [::nano::internal::generateKey]

	if {$outputFormat eq "hex"} {
		set retval [binary encode hex $retval]
	}

	return $retval
}

proc ::nano::key::fromSeed {seed args} {
	set index 0
	set outputFormat "bytes"
	if {[llength $args] > 0} {
		if {[string index [lindex $args 0] 0] ne "-"} {
			set index [lindex $args 0]
			set args [lrange $args 1 end]
		}

		foreach arg $args {
			switch -exact -- $arg {
				"-hex" {
					set outputFormat "hex"
				}
				"-binary" {
					set outputFormat "bytes"
				}
				default {
					return -code error "Invalid option: $arg"
				}
			}
		}
	}
	if {[string length $seed] != $::nano::key::seedLength} {
		set seed [binary decode hex $seed]
	}

	set key [::nano::internal::generateKey $seed $index]
	if {$outputFormat eq "hex"} {
		set key [binary encode hex $key]
	}

	return $key
}

proc ::nano::key::publicKeyFromPrivateKey {privateKey args} {
	set outputFormat "bytes"
	foreach arg $args {
		switch -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	if {[string length $privateKey] != $::nano::key::privateKeyLength} {
		set privateKey [binary decode hex $privateKey]
	}

	set pubKey [::nano::internal::publicKey $privateKey]
	if {$outputFormat eq "hex"} {
		set pubKey [string toupper [binary encode hex $pubKey]]
	}

	return $pubKey
}

# Low-level block management
proc ::nano::block::dict::toBlock {blockDict} {
	array set block $blockDict

	switch -- $block(type) {
		"state" {
			append blockData [::nano::address::toPublicKey $block(account)]
			append blockData [binary decode hex $block(previous)]
			append blockData [::nano::address::toPublicKey $block(representative)]
			append blockData [binary decode hex [format %032llX $block(balance)]]
			if {![info exists block(link)] && [info exists block(link_as_account)]} {
				append blockData [::nano::address::toPublicKey $block(link_as_account)]
			} else {
				append blockData [binary decode hex $block(link)]
			}
		}
		"open" {
			append blockData [binary decode hex $block(source)]
			append blockData [::nano::address::toPublicKey $block(representative)]
			append blockData [::nano::address::toPublicKey $block(account)]
		}
		"send" {
			append blockData [binary decode hex $block(previous)]
			append blockData [::nano::address::toPublicKey $block(destination)]
			append blockData [binary decode hex [format %032llX $block(balance)]]
		}
		"receive" {
			append blockData [binary decode hex $block(previous)]
			append blockData [binary decode hex $block(source)]
		}
		"change" {
			append blockData [binary decode hex $block(previous)]
			append blockData [::nano::address::toPublicKey $block(representative)]
		}
		default {
			return -code error "Invalid block type $block(type)"
		}
	}

	return $blockData
}

proc ::nano::block::json::toBlock {blockJSON} {
	set blockDict [::nano::block::dict::fromJSON $blockJSON]
	tailcall ::nano::block::dict::toBlock $blockDict
}

proc ::nano::block::dict::fromJSON {blockJSON} {
	set retval [::json::json2dict $blockJSON]

	if {[dict get $retval "type"] eq "send"} {
		set balance [dict get $retval "balance"]
		set balance [format %lli "0x$balance"]
		dict set retval "balance" $balance
	}

	# Parse out the work data
	if {[dict get $retval "type"] in {send receive change state}} {
		set workDataBasedOn "previous"
	}

	if {[dict get $retval "type"] eq "state" && [dict get $retval "previous"] eq $::nano::block::zero && [dict get $retval "link"] eq $::nano::block::zero} {
		set workDataBasedOn "account"
	}

	if {[dict get $retval "type"] eq "open"} {
		set workDataBasedOn "account"
	}

	if {[info exists workDataBasedOn]} {
		if {$workDataBasedOn eq "previous"} {
			dict set retval "_workData" [dict get $retval "previous"]
		} else {
			dict set retval "_workData" [::nano::address::toPublicKey [dict get $retval "account"]]
		}
	}

	return $retval
}

proc ::nano::block::json::fromDict {blockDict} {
	array set block $blockDict

	if {$block(type) eq "state"} {
		if {![info exists block(link)]} {
			set block(link) [::nano::address::toPublicKey $block(link_as_account) -hex]
		}

		if {![info exists block(link_as_address)]} {
			set addressFormatFlag "-nano"
			foreach field {account destination representative} {
				if {![info exists block($field)]} {
					continue
				}
				if {[string match "nano_*" $block($field)]} {
					set addressFormatFlag "-nano"
				} else {
					set addressFormatFlag "-xrb"
				}

				break
			}

			set block(link_as_account) [::nano::address::fromPublicKey $block(link) $addressFormatFlag]
		}
	}

	set blockJSONFields {
		type account source destination previous representative balance
		link link_as_account _blockHash _workData work signature _comment
	}

	set blockJSONEntries [lmap field $blockJSONFields {
		if {![info exists block($field)]} {
			continue
		}

		switch -exact -- $field {
			"source" - "previous" - "link" - "_blockHash" - "_workData" {
				if {[string length $block($field)] == $::nano::block::hashLength} {
					set block($field) [binary encode hex $block($field)]
				}

				set block($field) [string toupper $block($field)]
			}
			"signature" {
				if {[string length $block($field)] == $::nano::block::signatureLength} {
					set block($field) [binary encode hex $block($field)]
				}

				set block($field) [string toupper $block($field)]
			}
			"work" {
				if {[string length $block($field)] == $::nano::work::workValueLength} {
					set block($field) [binary encode hex $block($field)]
				}

				set block($field) [string tolower $block($field)]
			}
			"balance" {
				if {$block(type) in {send receive change open}} {
					set balanceFormatStr %032llx
				} else {
					set balanceFormatStr %lli
				}
				set block($field) [string toupper [format $balanceFormatStr "$block($field)"]]
			}
		}

		return -level 0 [list $field [json::write string $block($field)]]
	}]
	set blockJSONEntries [join $blockJSONEntries]

	set blockJSON [json::write object {*}$blockJSONEntries]

	return $blockJSON
}

proc ::nano::block::typeIDFromType {type args} {
	set outputFormat decimal
	foreach arg $args {
		switch -exact -- $arg {
			"-dec" - "-decimal" {
				set outputFormat "decimal"
			}
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	switch -- $type {
		"invalid"     { set typeId 0 }
		"not_a_block" { set typeId 1 }
		"send"        { set typeId 2 }
		"receive"     { set typeId 3 }
		"open"        { set typeId 4 }
		"change"      { set typeId 5 }
		"state"       { set typeId 6 }
		default       { error "Invalid type: $type" }
	}

	switch -- $outputFormat {
		"decimal" {
			set result $typeId
		}
		"hex" {
			set result [format %02x $typeId]
		}
		"bytes" {
			set result [binary decode hex [format %02x $typeId]]
		}
	}

	return $result
}

proc ::nano::block::typeFromTypeID {typeId args} {
	set inputFormat decimal
	foreach arg $args {
		switch -exact -- $arg {
			"-dec" - "-decimal" {
				set inputFormat "decimal"
			}
			"-hex" {
				set inputFormat "hex"
			}
			"-binary" {
				set inputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	switch -- $inputFormat {
		"decimal" { }
		"hex" {
			if {![string match "0x*" $typeId]} {
				set typeId "0x${typeId}"
			}
		}
		"bytes" {
			set typeId [binary encode hex $typeId]
			set typeId "0x${typeId}"
		}
	}

	switch -- [format %i $typeId] {
		0 { set type "invalid" }
		1 { set type "not_a_block" }
		2 { set type "send" }
		3 { set type "receive" }
		4 { set type "open" }
		5 { set type "change" }
		6 { set type "state" }
		default {
			error "Invalid type ID: $typeId"
		}
	}

	return $type
}

proc ::nano::block::lengthFromType {type args} {
	set includeType false
	set includeWork false
	set includeSig  false
	foreach arg $args {
		switch -exact -- $arg {
			"-full" {
				set includeType true
				set includeWork true
				set includeSig  true
			}
			"-work" {
				set includeWork true
			}
			"-signature" {
				set includeSig  true
			}
			"-type" {
				set includeType true
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	switch -- $type {
		"invalid" - "not_a_block" {
			set length 0
			set includeWork false
			set includeSig false
		}
		"state"   { set length 144 }
		"open"    { set length 96  }
		"send"    { set length 80  }
		"receive" { set length 64  }
		"change"  { set length 64  }
		default {
			return -code error "Unknown type: $type"
		}
	}

	if {$includeType} {
		incr length
	}

	if {$includeWork} {
		incr length 8
	}

	if {$includeSig} {
		incr length 64
	}

	return $length
}

proc ::nano::block::typeFromLength {length} {
	switch -- $length {
		144 { set type state }
		96  { set type open  }
		80  { set type send  }
		default {
			return -code error "Ambigious"
		}
	}

	return $type
}

proc ::nano::block::dict::fromBlock {blockData args} {
	set block(_blockData) $blockData
	set block(type) ""
	set addressPrefix "nano_"
	foreach arg $args {
		switch -glob -- $arg {
			"-type=*" {
				set block(type) [lindex [split $arg =] 1]
			}
			"-signKey=*" {
				set block(signKey) [string range $arg 9 end]
			}
			"-xrb" {
				set addressPrefix "xrb_"
			}
			"-nano" {
				set addressPrefix "nano_"
			}
			default {
			}
		}
	}

	if {$block(type) eq ""} {
		if {[catch {
			set block(type) [::nano::block::typeFromLength [string length $blockData]]
		}]} {
			return -code error "Unable to parse block, must specify type"
		}
	}

	set addArgs_fromPublicKey [list]
	if {$addressPrefix eq "xrb_"} {
		lappend addArgs_fromPublicKey "-xrb"
	}

	switch -- $block(type) {
		"state" {
			binary scan $blockData a32H64a32H32H64H128H16 \
				block(account) \
				block(previous) \
				block(representative) \
				block(balance) \
				block(link) \
				block(signature) \
				block(work)
		}
		"open" {
			binary scan $blockData H64a32a32H128H16 \
				block(source) \
				block(representative) \
				block(account) \
				block(signature) \
				block(work)

			set block(_workData) $block(account)
		}
		"send" {
			binary scan $blockData H64a32H32H128H16 \
				block(previous) \
				block(destination) \
				block(balance) \
				block(signature) \
				block(work)

			set block(_workData) $block(previous)
		}
		"receive" {
			binary scan $blockData H64H64H128H16 \
				block(previous) \
				block(source) \
				block(signature) \
				block(work)

			set block(_workData) $block(previous)
		}
		"change" {
			binary scan $blockData H64a32H128H16 \
				block(previous) \
				block(representative) \
				block(signature) \
				block(work)

			set block(_workData) $block(previous)
		}
		default {
			return -code error "Invalid block type: $block(type)"
		}
	}

	foreach field {account representative link_as_account destination balance work signature} {
		if {![info exists block($field)]} {
			continue
		}

		switch -exact -- $field {
			"account" - "representative" - "link_as_account" - "destination" {
				set block($field) [::nano::address::fromPublicKey $block($field) {*}$addArgs_fromPublicKey]
			}
			"balance" {
				set block($field) [format %lli "0x$block($field)"]
			}
		}
	}


	return [array get block]
}

proc ::nano::block::json::fromBlock {blockData args} {
	set blockDict [::nano::block::dict::fromBlock $blockData {*}$args]

	set blockJSON [::nano::block::json::fromDict $blockDict]

	return $blockJSON
}

proc ::nano::block::_hash {blockData args} {
	set outputFormat "bytes"
	foreach arg $args {
		switch -exact -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set hash [::nano::internal::hashData $blockData $::nano::block::hashLength]

	if {$outputFormat eq "hex"} {
		set hash [string toupper [binary encode hex $hash]]
	}

	return $hash
}

proc ::nano::block::dict::toHash {blockDict args} {
	if {[dict get $blockDict type] eq "state"} {
		set blockData $::nano::block::stateBlockPreamble
	}

	append blockData [::nano::block::dict::toBlock $blockDict]

	tailcall ::nano::block::_hash $blockData {*}$args
}

proc ::nano::block::json::toHash {blockJSON args} {
	set blockDict [::nano::block::dict::fromJSON $blockJSON]

	tailcall ::nano::block::dict::toHash $blockDict {*}$args
}

proc ::nano::block::signBlockHash {blockHash privateKey args} {
	set outputFormat "bytes"
	foreach arg $args {
		switch -exact -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	if {[string length $privateKey] != $::nano::key::privateKeyLength} {
		set privateKey [binary decode hex $privateKey]
	}

	set signature [::nano::internal::signDetached $blockHash $privateKey]

	if {$outputFormat eq "hex"} {
		set signature [string toupper [binary encode hex $signature]]
	}

	return $signature
}

proc ::nano::block::_sign {blockData args} {
	set blockHash [::nano::block::_hash $blockData]

	tailcall ::nano::block::signBlockHash $blockHash {*}$args
}

proc ::nano::block::verifyBlockHash {blockHash signature publicKey} {
	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	if {[string length $signature] != $::nano::block::signatureLength} {
		set signature [binary decode hex $signature]
	}

	if {[string length $publicKey] != $::nano::key::publicKeyLength} {
		set publicKey [binary decode hex $publicKey]
	}

	set valid [::nano::internal::verifyDetached $blockHash $signature $publicKey]

	return $valid
}

proc ::nano::block::_verifyBlock {blockData args} {
	set blockHash [::nano::block::_hash $blockData]

	tailcall ::nano::block::verifyBlockHash $blockHash {*}$args
}

proc ::nano::block::dict::_addBlockData {blockDict} {
	if {[dict exists $blockDict _blockData]} {
		return $blockDict
	}

	set blockData [::nano::block::dict::toBlock $blockDict]

	dict set blockDict _blockData $blockData

	return $blockDict
}

proc ::nano::block::dict::_addBlockHash {blockDict} {
	if {[dict exists $blockDict _blockHash]} {
		return $blockDict
	}

	set blockDict [_addBlockData $blockDict]
	set blockData [dict get $blockDict _blockData]

	if {[dict get $blockDict type] eq "state"} {
		set blockData "${::nano::block::stateBlockPreamble}${blockData}"
	}

	set blockHash [::nano::block::_hash $blockData -binary]

	dict set blockDict _blockHash $blockHash

	return $blockDict
}

proc ::nano::block::dict::sign {blockDict privateKey args} {
	set outputMode "signature"
	set outputFormat "bytes"
	foreach arg $args {
		switch -- $arg {
			"-update" {
				set outputMode "update"
			}
			"-signature" {
				set outputMode "signature"
			}
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set blockDict [_addBlockHash $blockDict]

	set blockHash [dict get $blockDict _blockHash]

	set signature [::nano::block::signBlockHash $blockHash $privateKey -binary]

	if {$outputMode eq "signature"} {
		if {$outputFormat eq "hex"} {
			set signature [binary encode hex $signature]
		}

		return $signature
	}

	dict set blockDict signature $signature

	return $blockDict
}

proc ::nano::block::json::sign {blockJSON privateKey args} {
	set outputMode "signature"
	foreach arg $args {
		switch -- $arg {
			"-update" {
				set outputMode "update"
			}
			"-signature" {
				set outputMode "signature"
			}
			"-hex" - "-binary" {}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set blockDict [::nano::block::dict::fromJSON $blockJSON]

	set retval [::nano::block::dict::sign $blockDict $privateKey {*}$args]

	if {$outputMode eq "signature"} {
		return $retval
	}

	set retval [::nano::block::json::fromDict $retval]

	return $retval
}

proc ::nano::block::dict::verifySignature {blockDict} {
	set publicKey [::nano::address::toPublicKey [dict get $blockDict account]]
	set signature [dict get $blockDict signature]

	set blockDict [_addBlockHash $blockDict]

	set blockHash [dict get $blockDict _blockHash]

	tailcall ::nano::block::verifyBlockHash $blockHash $signature $publicKey
}

proc ::nano::block::json::verifySignature {blockJSON} {
	set blockDict [::nano::block::dict::fromJSON $blockJSON]

	tailcall ::nano::block::dict::verifySignature $blockDict
}

proc ::nano::block::dict::work {blockDict args} {
	set outputMode "work"
	set outputFormat "hex"
	foreach arg $args {
		switch -- $arg {
			"-update" {
				set outputMode "update"
			}
			"-work" {
				set outputMode "work"
			}
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set blockDict [_addBlockHash $blockDict]

	set blockHash [dict get $blockDict _workData]

	set work [::nano::work::fromWorkData $blockHash -binary]

	if {$outputMode eq "work"} {
		if {$outputFormat eq "hex"} {
			set work [binary encode hex $work]
		}

		return $work
	}

	dict set blockDict work $work

	return $blockDict
}

proc ::nano::block::json::work {blockJSON args} {
	set outputMode "work"
	foreach arg $args {
		switch -- $arg {
			"-update" {
				set outputMode "update"
			}
			"-work" {
				set outputMode "work"
			}
			"-hex" - "-binary" {}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	set blockDict [::nano::block::dict::fromJSON $blockJSON]

	set retval [::nano::block::dict::work $blockDict {*}$args]

	if {$outputMode eq "work"} {
		return $retval
	}

	set retval [::nano::block::json::fromDict $retval]

	return $retval
}

proc ::nano::block::dict::validateWork {blockDict} {
	set blockDict [_addBlockHash $blockDict]

	set blockHash [dict get $blockDict _workData]
	set work      [dict get $blockDict work]

	tailcall ::nano::work::validate $blockHash $work
}

proc ::nano::block::json::validateWork {blockJSON} {
	set blockDict [::nano::block::dict::fromJSON $blockJSON]

	tailcall ::nano::block::dict::validateWork $blockDict
}

proc ::nano::block::json::filter {blockJSON} {
	set blockDict [::nano::block::dict::fromJSON $blockJSON]
	set blockDict [dict filter $blockDict script {key _} {
		if {[string match "_*" $key]} {
			continue
		}

		return -level 0 true
	}]
	set blockJSON [::nano::block::json::fromDict $blockDict]
	return $blockJSON
}

proc ::nano::block::json::genesis {network} {
	return $::nano::block::genesis($network)
}

proc ::nano::block::dict::genesis {network} {
	if {![info exists ::nano::block::dict::genesis($network)]} {
		set ::nano::block::dict::genesis($network) [::nano::block::dict::fromJSON [::nano::block::json::genesis $network]]
	}

	return $::nano::block::dict::genesis($network)
}

#   send from <account> to <account> previousBalance <balance>
#        amount <amount> sourceBlock <sourceBlockHash>
#        previous <previousBlockHash> ?representative <representative>?
proc ::nano::block::create::send {args} {
	array set block $args
	if {![info exists block(representative)]} {
		set block(representative) $block(from)
	}

	set block(balance) [expr {$block(previousBalance) - $block(amount)}]

	set blockDict [dict create \
		"type" state \
		"account" $block(from) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link_as_account" $block(to) \
		"_workData" $block(previous) \
		"_comment" "Send $block(amount) raw from $block(from) to $block(to)" \
	]

	if {[info exists block(signKey)]} {
		set blockDict [::nano::block::dict::sign $blockDict $block(signKey) -update]
	}

	if {[info exists block(-json)] && $block(-json)} {
		return [::nano::block::json::fromDict $blockDict]
	}

	return $blockDict
}

# Usage:
#   receive to <account> previousBalance <balance> amount <amount>
#           sourceBlock <sourceBlockHash> ?previous <previousBlockHash>?
#           ?representative <representative>?
proc ::nano::block::create::receive {args} {
	array set block $args

	if {![info exists block(representative)]} {
		set block(representative) $block(to)
	}

	if {![info exists block(previous)]} {
		set block(previous) $::nano::block::zero
		set block(previousBalance) 0
		set block(_workData) [::nano::address::toPublicKey $block(to) -hex]
	} else {
		set block(_workData) $block(previous)
	}

	set block(balance) [expr {$block(previousBalance) + $block(amount)}]

	set blockDict [dict create \
		"type" state \
		"account" $block(to) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link" $block(sourceBlock) \
		"_workData" $block(_workData) \
		"_comment" "Receive $block(amount) raw on $block(to) from hash $block(sourceBlock)" \
	]

	if {[info exists block(signKey)]} {
		set blockDict [::nano::block::dict::sign $blockDict $block(signKey) -update]
	}

	if {[info exists block(-json)] && $block(-json)} {
		return [::nano::block::json::fromDict $blockDict]
	}

	return $blockDict
}

# Usage:
#   setRepresentative account <account> previous <previousBlockHash>
#                     representative <newRepresentative> balance <balance>
proc ::nano::block::create::setRepresentative {args} {
	array set block $args

	set block(link) $::nano::block::zero

	set blockDict [dict create \
		"type" state \
		"account" $block(account) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link" $block(link) \
		"_workData" $block(previous) \
	]

	if {[info exists block(signKey)]} {
		dict set blockDict signKey $block(signKey)
	}

	if {[info exists block(signKey)]} {
		set blockDict [::nano::block::dict::sign $blockDict $block(signKey) -update]
	}

	if {[info exists block(-json)] && $block(-json)} {
		return [::nano::block::json::fromDict $blockDict]
	}

	return $blockDict
}

# Work generation functions
proc ::nano::work::fromWorkData {blockHashOrPublicKey args} {
	set outputFormat "hex"
	foreach arg $args {
		switch -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
			default {
				return -code error "Invalid option: $arg"
			}
		}
	}

	if {[string length $blockHashOrPublicKey] != $::nano::block::hashLength} {
		set blockHashOrPublicKey [binary decode hex $blockHashOrPublicKey]
	}

	set work [::nano::internal::generateWork $blockHashOrPublicKey]

	if {$outputFormat eq "hex"} {
		set work [binary encode hex $work]
		set work [string tolower $work]
	}

	return $work
}

proc ::nano::work::fromBlock {blockData} {
	set blockDict [::nano::block::dict::fromBlock $blockData]
	set workData  [dict get $blockDict _workData]

	tailcall ::nano::work::fromBlockhash $workData
}

proc ::nano::work::validate {workData work} {
	if {[string length $workData] != $::nano::block::hashLength} {
		set workData [binary decode hex $workData]
	}

	if {[string length $work] != $::nano::work::workValueLength} {
		set work [binary decode hex $work]
	}

	tailcall ::nano::internal::validateWork $workData $work
}

# High level account management
proc ::nano::account::setFrontier {account frontierHash balance representative} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]
	set ::nano::account::frontiers($accountPubKey) [dict create \
		frontierHash $frontierHash balance $balance representative $representative \
	]
}

proc ::nano::account::getFrontier {account args} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]
	if {![info exists ::nano::account::frontiers($accountPubKey)]} {
		set frontier [dict create balance 0]
	} else {
		set frontier $::nano::account::frontiers($accountPubKey)
	}

	return [dict get $frontier {*}$args]
}

proc ::nano::account::addPending {account blockHash amount} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	dict set ::nano::account::pending $accountPubKey $blockHash amount $amount
}

proc ::nano::account::getPending {account args} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	set retval [dict create]
	catch {
		set retval [dict get $::nano::account::pending $accountPubKey {*}$args]
	}

	return $retval
}

proc ::nano::account::clearPending {account args} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	catch {
		dict unset ::nano::account::pending $accountPubKey {*}$args
	}

	return
}

proc ::nano::account::receive {account blockHash signKey} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	set frontierInfo [getFrontier $account]
	dict with frontierInfo {}

	set blockInfo [getPending $account $blockHash]

	if {![info exists representative]} {
		set representative $account
	}

	set amount [dict get $blockInfo amount]
	set blockArgs [list to $account previousBalance $balance \
	                    amount $amount sourceBlock $blockHash \
	                    signKey $signKey representative $representative]

	if {[info exists frontierHash]} {
		lappend blockArgs previous $frontierHash
	}

	dict set blockArgs -json true

	set block [::nano::block::create::receive {*}$blockArgs]

	set newFrontierHash [dict get [json::json2dict $block] "_blockHash"]
	set balance [expr {$balance + $amount}]

	setFrontier $account $newFrontierHash $balance $representative
	clearPending $account $blockHash

	return $block
}

proc ::nano::account::send {fromAccount toAccount amount signKey} {
	set fromAccountPubKey [::nano::address::toPublicKey $fromAccount -hex]
	set toAccountPubKey   [::nano::address::toPublicKey $fromAccount -hex]

	set fromFrontierInfo [getFrontier $fromAccount]
	set toFrontierInfo [getFrontier $toAccount]

	set fromBalance [dict get $fromFrontierInfo balance]
	set fromFrontierHash [dict get $fromFrontierInfo frontierHash]
	set fromRepresentative [dict get $fromFrontierInfo representative]

	set signKey [binary encode hex $signKey]

	set block [::nano::block::create::send \
		from            $fromAccount \
		to              $toAccount \
		previous        $fromFrontierHash \
		previousBalance $fromBalance \
		amount          $amount \
		signKey         $signKey \
		-json           true
	]

	set newBalance [expr {$fromBalance - $amount}]
	set newFrontierHash [dict get [json::json2dict $block] "_blockHash"]

	setFrontier $fromAccount $newFrontierHash $newBalance $fromRepresentative
	addPending  $toAccount $newFrontierHash $amount

	return $block
}

proc ::nano::account::receiveAllPending {key {accountPubKey ""}} {
	set outBlocks [list]

	if {$accountPubKey eq ""} {
		set accountPubKey [::nano::key::publicKeyFromPrivateKey $key -hex]
	}

	set account [::nano::address::fromPublicKey $accountPubKey]

	set pendingBlocks [getPending $account]
	if {[llength $pendingBlocks] == 0} {
		return $outBlocks
	}

	set signKey [binary encode hex $key]

	foreach blockHash [dict keys $pendingBlocks] {
		lappend outBlocks [receive $account $blockHash $signKey]
	}

	return $outBlocks
}

proc ::nano::account::setRepresentative {account representative signKey} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	set frontierInfo [getFrontier $account]
	dict with frontierInfo {}

	set blockArgs [list account $account \
	                    representative $representative \
	                    signKey $signKey \
	                    previous $frontierHash \
	]
	dict set blockArgs -json true

	set block [::nano::block::create::setRepresentative {*}$blockArgs]

	set newFrontierHash [dict get [json::json2dict $block] "_blockHash"]

	setFrontier $account $newFrontierHash $balance $representative

	return $block
}

# Ledger
proc ::nano::ledger::lmdb::init {configDict} {
	package require lmdb

	array set config $configDict

	if {[info exists config(configDirectory)]} {
		set config(file) [file join $config(configDirectory) $config(file)]
	}
	set config(file) [file normalize $config(file)]

	set envHandle [lmdb env]
	$envHandle set_maxdbs 32
	$envHandle set_mapsize 1099511627776
	$envHandle open -path $config(file) -nosubdir true -readonly false

	set lmdbInfo [dict create \
		envHandle     $envHandle \
	]

	set handle [list apply {{lmdbInfo proc args} {
		tailcall ::nano::ledger::lmdb::$proc $lmdbInfo {*}$args
	}} $lmdbInfo]

	return $handle
}

proc ::nano::ledger::lmdb::_transaction {lmdbInfo table cursorVar code} {
	set table [split $table /]
	set readOnly true
	foreach arg [lrange $table 1 end] {
		switch -- $arg {
			"write" {
				set readOnly false
			}
			"read" {
				set readOnly true
			}
		}
	}
	set table [lindex $table 0]

	set envHandle [dict get $lmdbInfo envHandle]
	set dbHandle [lmdb open -env $envHandle -name $table]
	set sessionHandle [$envHandle txn -readonly $readOnly]
	set cursor [$dbHandle cursor -txn $sessionHandle]

	uplevel 1 [list set $cursorVar $cursor]
	set retcode [catch {uplevel 1 $code} retval options]

	$cursor close
	if {$retcode == 0} {
		$sessionHandle commit
	} else {
		if {$readOnly} {
			$sessionHandle reset
		} else {
			$sessionHandle abort
		}
	}
	$sessionHandle close
	$dbHandle close -env $envHandle

	if {$retcode == 0} {
		return $retval
	}

	return {*}$options $retval
}

proc ::nano::ledger::lmdb::_foreach {lmdbInfo table cursorVar keyVar valueVar args} {
	set code [lindex $args end]
	set args [lrange $args 0 end-1]

	if {[llength $args] == 0} {
		set initialize [list getBinary "-first"]
	} else {
		if {[lindex $args 0] eq "-set"} {
			set checkKeyEqual [lindex $args 1]
		}

		set initialize [list getBinary {*}$args]
	}
	set iterate [list getBinary "-next"]

	_transaction $lmdbInfo $table cursor {
		if {$cursorVar ne ""} {
			uplevel 1 [list set $cursorVar $cursor]
		}

		for {
			if {[catch {
				set work [$cursor {*}$initialize]
			} err]} {
				if {[string match "ERROR: MDB_NOTFOUND: *" $err]} {
					return
				}

				return -code error $err
			}
		} true {
			if {[catch {
				set work [$cursor {*}$iterate]
			} err]} {
				if {[string match "ERROR: MDB_NOTFOUND: *" $err]} {
					break
				}

				return -code error $err
			}
		} {
			unset -nocomplain key

			if {[info exists checkKeyEqual]} {
				set key [lindex $work 0]
				if {$key ne $checkKeyEqual} {
					break
				}
			}

			if {$keyVar ne ""} {
				if {![info exists key]} {
					set key [lindex $work 0]
				}
				uplevel 1 [list set $keyVar $key]
			}

			if {$valueVar ne ""} {
				set value [lindex $work 1]
				uplevel 1 [list set $valueVar $value]
			}

			catch {uplevel 1 $code} retval options

			switch -- [dict get $options "-code"] {
				4 - 0 {
					# TCL_CONTINUE or TCL_OK
					continue
				}
				1 {
					# TCL_ERROR, pass it on
					dict set options "-level" 1
					return {*}$options $retval
				}
				2 {
					# TCL_RETURN
					return -level 2 $retval
				}
				3 {
					# TCL_BREAK
					break
				}
			}
		}
	}

	return
}

# XXX:TODO: Track down why this speeds things up >10x
interp alias {} ::nano::ledger::lmdb::_magicSpeedup {} time

proc ::nano::ledger::lmdb::getPending {lmdbInfo args} {
	if {[llength $args] > 0} {
		set account [lindex $args 0]
		set accountPubKey [::nano::address::toPublicKey $account -binary]
		append searchKey $accountPubKey

		set args [lrange $args 1 end]
	}

	if {[llength $args] > 0} {
		set blockHash [lindex $args 0]
		if {[string length $blockHash] != $::nano::block::hashLength} {
			set blockHash [binary decode hex $blockHash]

			append searchKey $blockHash
		}

		set args [lrange $args 1 end]
	}

	set retval [list]

	if {[info exists searchKey]} {
		set searchKey [list "-set_range" $searchKey]
	} else {
		set searchKey [list]
	}

	_foreach $lmdbInfo "pending" cursor key value {*}$searchKey {
		set keyAccountPubKey [string range $key 0 31]
		if {[info exists accountPubKey] && $keyAccountPubKey ne $accountPubKey} {
			break
		}

		set keyBlockHash [string range $key 32 63]
		if {[info exists blockHash] && $keyBlockHash ne $blockHash} {
			break
		}

		set from [string range $value 0 31]
		set amount [string range $value 32 47]

		set itemDict [dict create \
			amount [format "%lli" 0x[binary encode hex $amount]] \
			from   [::nano::address::fromPublicKey $from] \
		]

		if {[info exists blockHash]} {
			set retval $itemDict

			break
		}

		set keyBlockHashHex [string toupper [binary encode hex $keyBlockHash]]

		if {[info exists accountPubKey]} {
			_magicSpeedup {
				dict set retval $keyBlockHashHex [set itemDict]
			}
		} else {
			set keyAccountPubKeyHex [string toupper [binary encode hex $keyAccountPubKey]]

			_magicSpeedup {
				dict set retval $keyAccountPubKeyHex $keyBlockHashHex $itemDict
			}
		}
	}

	if {[info exists blockHash] && [llength $args] > 0} {
		set retval [dict get $retval {*}$args]
	}

	return $retval
}

proc ::nano::ledger::lmdb::clearPending {lmdbInfo account args} {
	set accountPubKey [::nano::address::toPublicKey $account -binary]

	if {[llength $args] > 1} {
		return -code error "wrong # args: clearPending <lmdbInfo> <account> ?<blockHash>?"
	}

	if {[llength $args] == 1} {
		set blockHash [lindex $args 0]
		if {[string length $blockHash] != $::nano::block::hashLength} {
			set blockHash [binary decode hex $blockHash]
		}
		set searchKey "${accountPubKey}${blockHash}"

		set numberOfRowsDeleted 0

		_foreach $lmdbInfo "pending/write" cursor "" "" -set $searchKey {
			$cursor del

			incr numberOfRowsDeleted
		}

		return $numberOfRowsDeleted
	}

	set numberOfRowsDeleted 0
	set blockHashDict [getPending $lmdbInfo $account]
	foreach blockHash [dict keys $blockHashDict] {
		incr numberOfRowsDeleted [clearPending $lmdbInfo $account $blockHash]
	}

	return $numberOfRowsDeleted
}

proc ::nano::ledger::lmdb::addPending {lmdbInfo account blockHash args} {
	set accountPubKey [::nano::address::toPublicKey $account -binary]

	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	set lmdbKey "${accountPubKey}${blockHash}"
	set fromHex [::nano::address::toPublicKey [dict get $args from] -hex]
	set amountHex [format %032llx [dict get $args amount]]
	set lmdbData [binary format H64H32 $fromHex $amountHex]

	set keyExists false
	_foreach $lmdbInfo "pending" "" "" "" -set $lmdbKey {
		set keyExists true
	}

	if {!$keyExists} {
		_transaction $lmdbInfo "pending/write" cursor {
			$cursor putBinary $lmdbKey $lmdbData
		}
	}

	return
}

# Node Configuration
proc ::nano::node::_configDictToJSON {configDict {prefix ""} {keyPattern ""}} {
	if {$keyPattern eq ""} {
		set keyPattern "*"
	}
	set values [list]
	foreach key [dict keys $configDict $keyPattern] {
		set value [dict get $configDict $key]
		switch -- ${prefix}${key} {
			"rpc" - "node" - "opencl" - "node/logging" - "node/database" {
				set value [_configDictToJSON $value "$key/"]
			}
			"node/preconfigured_peers" - "node/preconfigured_representatives" - "node/work_peers" {
				set value [json::write array {*}[lmap item $value {
					json::write string $item
				}]]
			}
			default {
				set value [json::write string $value]
			}
		}

		lappend values $key $value
	}

	set json [json::write object {*}$values]

	return $json
}

proc ::nano::node::_defaultConfig {basis network} {
	# XXX:TODO: Finish setting up the defaults
	set default_topLevel [dict create \
		"version"        2 \
		"rpc_enable"     false \
	]

	catch {
		set basis_rpc [dict create]
		set basis_rpc [dict get $basis "rpc"]
	}
	set default_rpc [dict create \
		"address"        "::ffff:127.0.0.1" \
		"port"           7076 \
	]

	catch {
		set basis_node [dict create]
		set basis_node [dict get $basis "node"]
	}
	set default_node [dict create \
		"client_id_private_key"     [::nano::key::newKey] \
		"bootstrap_connections" "4" \
	]

	# Configure based on network
	switch -- $network {
		"main" {
			dict set default_node "peering_port" "7075"
			dict set default_node "preconfigured_peers" [list "rai.raiblocks.net"]
		}
		"beta" {
			dict set default_node "peering_port" "54000"
			dict set default_node "preconfigured_peers" [list "rai-beta.raiblocks.net"]
		}
	}

	catch {
		set basis_node_database [dict create]
		set basis_node_database [dict get $basis "node" "database"]
	}
	set default_node_database [dict create \
		"backend"        "lmdb" \
		"file"           "data.ldb" \
	]

	set basis [dict merge $default_topLevel $basis]
	set basis_rpc [dict merge $default_rpc $basis_rpc]
	set basis_node [dict merge $default_node $basis_node]
	set basis_node_database [dict merge $default_node_database $basis_node_database]

	dict set basis rpc $basis_rpc
	dict set basis node $basis_node
	dict set basis node database $basis_node_database

	return $basis
}

# Side-effect:  Sets ::nano::node::configuration
proc ::nano::node::_loadConfigFile {file network} {
	set json "{}"
	catch {
		set fd [open $file]
		set json [read $fd]
	}
	catch {
		close $fd
	}

	set configuration [::json::json2dict $json]

	set configuration [_defaultConfig $configuration $network]

	set ::nano::node::configuration $configuration

	dict set ::nano::node::configuration network $network

	return $::nano::node::configuration
}

proc ::nano::node::_saveConfigFile {file args} {
	if {[llength $args] == 0} {
		set configDict $::nano::node::configuration
	} elseif {[llength $args] == 1} {
		set configDict [lindex $args 0]
	} else {
		return -code error "wrong # args: _saveConfigFile <file> ?<configDict>?"
	}

	set json [_configDictToJSON $configDict]
	set tmpfile "${file}.new"
	set fd [open "${tmpfile}" "w"]
	puts $fd $json
	close $fd
	file rename -force -- "${tmpfile}" "${file}"

	return true
}

proc ::nano::node::setLedgerHandle {handle} {
	set procs {
		getPending
		clearPending
		addPending
	}

	namespace eval ::nano::node::ledger {}

	foreach proc $procs {
		proc ::nano::node::ledger::$proc args [concat [list tailcall {*}$handle $proc] {{*}$args}]
	}
}

proc ::nano::node::configure {network args} {
	package require ip
	package require dns

	# Set default options
	switch -- $network {
		"main" {
			set info(-configDirectory) [file normalize ~/RaiBlocks]
		}
		"beta" {
			set info(-configDirectory) [file normalize ~/RaiBlocksBeta]
		}
		default {
			return -code error "Only main, and beta networks are supported right now"
		}
	}

	# Parse options to the configure
	array set info $args

	# Load configuration file
	set configFile [file join $info(-configDirectory) "config.json"]

	_loadConfigFile $configFile $network

	# Determine database backend and access information
	set database_config  [dict get $::nano::node::configuration "node" "database"]
	set database_backend [dict get $database_config "backend"]
	if {![dict exists $database_config "configDirectory"]} {
		dict set database_config "configDirectory" $info(-configDirectory)
	}

#	set dbHandle [::nano::ledger::${database_backend}::init $database_config]
#	::nano::node::setLedgerHandle $dbHandle
}

# Only replace this function if it doesn't already exist
if {[info command ::nano::node::user_log] eq ""} {
	proc ::nano::node::user_log {line} {
		puts stderr $line
	}
}

proc ::nano::node::log {message {level "debug"}} {
	set linePrefix ""
	foreach line [split $message "\n"] {
		::nano::node::user_log [format {%-40s %10s [%5s] %s} [::info coroutine] [clock seconds] $level ${linePrefix}$line]
		set linePrefix "    "
	}
}

proc ::nano::protocol::extensions::get {messageType extensions} {
	::set flags [list]
	foreach {checkFlagName checkFlag} [dict get $::nano::protocol::extensions $messageType] {
		if {($extensions & $checkFlag) == $checkFlag} {
			lappend flags $checkFlagName
		}
	}
	return $flags
}

proc ::nano::protocol::extensions::set {messageType extensionsVar flag} {
	upvar 1 $extensionsVar extensions
	::set value [dict get $::nano::protocol::extensions $messageType $flag]
	::set extensions [expr {$extensions | $value}]
}

proc ::nano::protocol::extensions::unset {messageType extensionsVar flag} {
	upvar 1 $extensionsVar extensions

	::set value [dict get $::nano::protocol::extensions $messageType $flag]
	::set extensions [expr {$extensions & ((~$value) & 0xffff)}]
}


proc ::nano::protocol::create::bulk_pull {account args} {
	set count 0
	set extensions 0
	foreach {arg argVal} $args {
		switch -exact -- $arg {
			"-end" {
				set end $argVal
			}
			"-count" {
				set count $argVal
			}
			"-partialOkay" - "-foreach" {
				# Ignored, used by response parser
			}
			default {
				error "Invalid option: $arg"
			}
		}
	}

	if {[string length $account] in {64 65} && [lindex [split $account _] 0] in {xrb nano}} {
		set accountPubKey [::nano::address::toPublicKey $account -binary]
	} elseif {[string length $account] != $::nano::key::publicKeyLength} {
		set accountPubKey [binary decode hex $account]
	} else {
		set accountPubKey $account
	}

	if {[info exists end]} {
		if {[string length $end] != $::nano::block::hashLength} {
			set end [binary decode hex $end]
		}
	} else {
		set end [binary decode hex $::nano::block::zero]
	}

	set request [binary format a32a32 \
		$accountPubKey \
		$end \
	]

	if {$count != 0} {
		::nano::protocol::extensions::set "bulk_pull" extensions "count_present"
		append request [binary format ciccc 0 $count 0 0 0]
	} else {
		::nano::protocol::extensions::unset "bulk_pull" extensions "count_present"
	}

	return [dict create extensions $extensions data $request]
}

proc ::nano::protocol::parse::bulk_pull_response {sock account args} {
	set partialOkay false
	foreach {arg argVal} $args {
		switch -exact -- $arg {
			"-end" {
				# Ignored, used by request creator
			}
			"-partialOkay" {
				set partialOkay $argVal
			}
			"-foreach" {
				set blockVar [lindex $argVal 0]
				set blockHandler [lindex $argVal 1]
			}
		}
	}

	set blocks [list]

	set success false

	while true {
		if {[catch {
			set type [::nano::network::_recv $sock 1]
		} err]} {
			::nano::node::log "Error from $sock: $err"
			break
		}

		set type [::nano::block::typeFromTypeID $type -binary]

		if {$type eq "not_a_block"} {
			if {[info exists blockHandler]} {
				uplevel 2 [list set $blockVar ""]
				catch [list uplevel 2 $blockHandler]
			}

			set success true

			break
		}

		set length [::nano::block::lengthFromType $type -work -signature]

		if {[catch {
			set block [::nano::network::_recv $sock $length]
		} err]} {
			::nano::node::log "Error from $sock: $err"
			break
		}

		set block [::nano::block::dict::fromBlock $block -type=$type]

		if {[info exists blockHandler]} {
			uplevel 2 [list set $blockVar $block]
			set blockHandlerCode [catch [list uplevel 2 $blockHandler] blockHandlerResult blockHandlerOptions]
			switch -exact -- $blockHandlerCode {
				0 {}
				1 { return {*}$blockHandlerOptions $blockHandlerResult }
				2 { error "Not implemented" }
				3 {
					set success true

					break
				}
				4 { continue }
			}
		} else {
			lappend blocks $block
		}
	}

	if {!$success} {
		if {!$partialOkay} {
			error "Failed to pull from $sock"
		} elseif {[info exists blockHandler]} {
			uplevel 2 [list set $blockVar "error"]
			catch [list uplevel 2 $blockHandler]
		}
	}

	return $blocks
}

proc ::nano::protocol::parse::bulk_pull {extensions messageData} {
	set flags [::nano::protocol::extensions::get "bulk_pull" $extensions]

	binary scan $messageData H64H64a* start end extra
	set retval [dict create start $start]

	if {$end ni $::nano::block::zero} {
		dict set retval end $end
	}

	if {"count_present" in $flags} {
		binary scan $extra cuic* _ count _
		dict set retval count $count
	}

	return $retval
}

proc ::nano::protocol::create::_bulk_pull_account_flagsParse {direction flag} {
	switch -- $direction {
		"toInt" {
			switch -- $flag {
				"" - "default" - "pendingHashAndAmount" {
					set flagValue 0
				}
				"pendingAddressOnly" {
					set flagValue 1
				}
				"pendingHashAmountAndAddress" {
					set flagValue 2
				}
				default {
					if {[string is integer -strict $flag]} {
						set flagValue $flag
					} else {
						return -code error "Invalid flag: $flag"
					}
				}
			}

			return $flagValue
		}
		"fromInt" {
			switch -- $flag {
				0 - "pendingHashAndAmount" - "" - "default" {
					set flagValue "pendingHashAndAmount"
				}
				1 - "pendingAddressOnly" {
					set flagValue "pendingAddressOnly"
				}
				2 - "pendingHashAmountAndAddress" {
					set flagValue "pendingHashAmountAndAddress"
				}
				default {
					return -code error "Invalid flag: $flag"
				}
			}

			return $flagValue
		}
	}

	return -code error "Invalid direction: $direction"
}

proc ::nano::protocol::create::bulk_pull_account {account {minPending 0} {flags ""}} {
	set accountPubKey [::nano::address::toPublicKey $account -binary]
	set minPendingHex [format %032llx $minPending]

	if {[string length $minPendingHex] > 32} {
		return -code error "Invalid amount: $minPending"
	}

	set flagsInt [_bulk_pull_account_flagsParse "toInt" $flags]

	return [dict create data [binary format a32H32c \
		$accountPubKey \
		$minPendingHex \
		$flagsInt \
	]]
}

proc ::nano::protocol::parse::bulk_pull_account_response {sock account {minPending 0} {flags ""}} {
	set frontierBlockhash [::nano::network::_recv $sock 32]
	set frontierBalance   [::nano::network::_recv $sock 16]

	set frontierBlockhash [binary encode hex $frontierBlockhash]
	set frontierBlockhash [string toupper $frontierBlockhash]

	set frontierBalance   [binary encode hex $frontierBalance]
	set frontierBalance 0x$frontierBalance
	set frontierBalance [expr {$frontierBalance}]

	set fullPendingInfo true
	set flags [_bulk_pull_account_flagsParse "fromInt" $flags]

	set fullPendingInfo true
	set fullPendingIncludesAddress false
	switch -- $flags {
		"pendingAddressOnly" {
			set fullPendingInfo false
		}
		"pendingHashAndAmount" {
			# This is the default option
		}
		"pendingHashAmountAndAddress" {
			set fullPendingIncludesAddress true
		}
	}

	set pendingInfo [list]
	set pendingAddToDict [list]
	while true {
		if {$fullPendingInfo} {
			set pendingBlockhash [binary encode hex [::nano::network::_recv $sock 32]]
			set pendingAmount    [binary encode hex [::nano::network::_recv $sock 16]]

			if {$fullPendingIncludesAddress} {
				set pendingFrom [binary encode hex [::nano::network::_recv $sock 32]]
				set pendingFromEncoded [::nano::address::fromPublicKey $pendingFrom]
				set pendingAddToDict [list from $pendingFromEncoded]
			}

			if {$pendingBlockhash eq $::nano::block::zero && $pendingAmount eq $::nano::balance::zero} {
				if {$fullPendingIncludesAddress} {
					if {$pendingFrom eq $::nano::address::zero} {
						break
					}
				} else {
					break
				}
			}

			set pendingBlockhash [string toupper $pendingBlockhash]
			set pendingAmount 0x$pendingAmount
			set pendingAmount [expr {$pendingAmount}]

			lappend pendingInfo [dict create \
				blockhash $pendingBlockhash \
				amount    $pendingAmount \
				{*}$pendingAddToDict \
			]
		} else {
			set pendingFrom [binary encode hex [::nano::network::_recv $sock 32]]

			if {$pendingFrom eq $::nano::address::zero} {
				break
			}

			set pendingFrom [::nano::address::fromPublicKey $pendingFrom]

			lappend pendingInfo [dict create \
				from $pendingFrom \
			]
		}
	}

	set retval [dict create \
		frontier \
			[dict create \
				blockhash $frontierBlockhash \
				balance $frontierBalance \
			] \
		pending $pendingInfo \
	]

	return $retval
}

proc ::nano::protocol::create::frontier_req {{startAccount ""} {age ""} {count ""}} {
	if {$startAccount eq ""} {
		set accountPubKey [binary decode hex $::nano::address::zero]
	} else {
		set accountPubKey [::nano::address::toPublicKey $startAccount -binary]
	}

	if {$age eq ""} {
		set age [expr {2**32-1}]
	}

	if {$count eq ""} {
		set count [expr {2**32-1}]
	}

	return [dict create data [binary format a32ii $accountPubKey $age $count]]
}

proc ::nano::protocol::create::node_id_handshake {types args} {
	array set argInfo $args
	set extensions 0
	set data ""

	if {[llength $types] < 1} {
		return -code error "Invalid types specified: (none)"
	}

	foreach type $types {
		if {$type in {"query" "response"}} {
			continue
		}

		return -code error "Invalid type specified: $type"
	}

	if {"query" in $types} {
		::nano::protocol::extensions::set "node_id_handshake" extensions "query"

		if {[string length $argInfo(-query)] != 32} {
			return -code error "Invalid input data"
		}

		append data $argInfo(-query)
	}

	if {"response" in $types} {
		::nano::protocol::extensions::set "node_id_handshake" extensions "response"

		if {![info exists argInfo(-privateKey)]} {
			set argInfo(-privateKey) [::nano::key::newKey]
		}

		set publicKey [::nano::key::publicKeyFromPrivateKey $argInfo(-privateKey) -binary]
		set signature [::nano::internal::signDetached $argInfo(-query) $argInfo(-privateKey)]

		if {[string length $argInfo(-query)] != 32} {
			return -code error "Invalid input data"
		}

		if {[string length $publicKey] != 32 || [string length $signature] != 64} {
			return -code error "Invalid output data"
		}

		set response [binary format a32a64 $publicKey $signature]

		append data $response
	}

	return [dict create extensions $extensions data $data]
}

proc ::nano::network::_localIP {version} {
	if {[info exists ::nano::network::_localIP($version)]} {
		return $::nano::network::_localIP($version)
	}

	## XXX:TODO: Work out a better system for determining ones own IP
	switch -exact -- $version {
		v4 {
			set url "http://ipv4.rkeene.org/whatismyip"
			set localIPPrefix "::ffff:"
		}
		v6 {
			set url "http://ipv6.rkeene.org/whatismyip"
			set localIPPrefix ""
		}
	}

	set localIP [exec curl -sS $url]
	if {$localIP eq ""} {
		return -code error "Unable to lookup local IP $version"
	}

	set localIP [string trim $localIP]
	set localIP "${localIPPrefix}${localIP}"

	set ::nano::network::_localIP($version) $localIP

	return $::nano::network::_localIP($version)
}

proc ::nano::protocol::create::keepalive {ipPortDictList args} {
	set retval ""

	# Allow creating an empty keepalive
	array set argInfo {
		-local true
	}
	array set argInfo $args

	if {$argInfo(-local)} {
		set localPort [dict get $::nano::node::configuration "node" "peering_port"]
		set ipPortDictListHead [list]
		foreach ipVersion {v4 v6} {
			unset -nocomplain localIP

			catch {
				set localIP [::nano::network::_localIP $ipVersion]
			}

			if {![info exists localIP]} {
				continue
			}

			lappend ipPortDictListHead [dict create address $localIP port $localPort]
		}
		set ipPortDictList [concat $ipPortDictListHead $ipPortDictList]
	}

	if {[llength $ipPortDictList] == 0} {
		return [dict create data ""]
	}

	while {[string length $retval] < 144} {
		foreach ipPortDict $ipPortDictList {
			set ip [dict get $ipPortDict address]
			set port [dict get $ipPortDict port]

			# Encode IP address as a byte array
			if {[::ip::version $ip] == 4} {
				# Convert to IPv6 if needed
				set ip "::ffff:$ip"
			}

			set ip [binary decode hex [string map [list ":" ""] [::ip::normalize $ip]]]

			# Encode port as a 16-bit integer in network byte order (big endian)
			set port [binary format s $port]

			append retval "${ip}${port}"
		}
	}

	return [dict create data [string range $retval 0 143]]
}

proc ::nano::protocol::create::confirm_req {blockDict} {
	set blockData [::nano::block::dict::toBlock $blockDict]
	set blockType [dict get $blockDict type] 
	set blockTypeID [::nano::block::typeIDFromType $blockType -decimal]

	set retval(blockType) $blockTypeID
	set retval(data) $blockData

	return [array get retval]
}

proc ::nano::protocol::parse::confirm_req {extensions blockData} {
	set blockTypeID [expr {($extensions >> 8) & 0x0f}]
	set blockType [::nano::block::typeFromTypeID $blockTypeID]
	set blockDict [::nano::block::dict::fromBlock $blockData -type=$blockType]
	set blockHash [::nano::block::dict::toHash $blockDict -hex]

	# XXX:TEMPORARY
	dict unset blockDict _blockData
	dict unset blockDict _workData

	set retval(blockType) $blockType
	set retval(block) $blockDict
	set retval(hash) $blockHash

	return [array get retval]
}

proc ::nano::protocol::parse::confirm_ack {extensions blockData} {
	set blockTypeID [expr {($extensions >> 8) & 0x0f}]
	set blockType [::nano::block::typeFromTypeID $blockTypeID]

	# Header
	binary scan $blockData H64H128wa* \
		retval(voteAccount) \
		retval(voteSignature) \
		retval(voteSequence) \
		newBlockData

	set blockData $newBlockData

	# Determine whether or not this is a vote-by-hash block 
	set voteType "full"
	if {$blockType eq "not_a_block"} {
		set voteType "hash-only"
	}
	set retval(voteType) $voteType

	# Generate the data to hash and verify
	set signedData ""
	if {$voteType eq "hash-only"} {
		### Vote-by-hash blocks have a prefix containing the bytes "vote "
		append signedData "vote "
	}

	# Process the vote data
	if {$voteType eq "hash-only"} {
		set retval(hashes) [list]
		while {[string length $blockData] >= 32} {
			binary scan $blockData H64a* hash blockData

			lappend retval(hashes) $hash
			append signedData [binary decode hex $hash]
		}
	} else {
		set blockDict [::nano::block::dict::fromBlock $blockData -type=$blockType]
		set blockHash [::nano::block::dict::toHash $blockDict -hex]
		append signedData [binary decode hex $blockHash]

		# XXX:TEMPORARY
		dict unset blockDict _blockData
		dict unset blockDict _workData

		set retval(blockType) $blockType
		set retval(hashes) [list $blockHash]
		set retval(block) $blockDict
	}

	# Add the sequence number to the signed data
	append signedData [binary format w $retval(voteSequence)]

	# Verify signature of the hash
	set valid false
	catch {
		set valid [::nano::internal::verifyDetached \
			[::nano::internal::hashData $signedData $::nano::block::hashLength] \
			[binary decode hex $retval(voteSignature)] \
			[binary decode hex $retval(voteAccount)] \
		]
	}

	# Convert the account to an account form
	set retval(voteAccount) [::nano::address::fromPublicKey $retval(voteAccount)]

	# If the signature is invalid, clean things up a bit
	if {!$valid} {
		set retval(valid) false

		# If the vote isn't valid, don't create entries regarding this vote
		foreach renameKey [array names retval] {
			if {$renameKey eq "valid"} {
				continue
			}

			set retval(invalid_${renameKey}) $retval($renameKey)
			unset retval $renameKey
		}
	} else {
		set retval(valid) true
	}

	return [array get retval]
}

proc ::nano::protocol::create {network messageType args} {
	set versionUsing 14
	set versionMin 13
	set versionMax $versionUsing
	set messageInfo(extensions) 0
	set messageInfo(blockType) 0

	set messageType [string tolower $messageType]
	set messageTypeID [lsearch -exact $::nano::network::messageTypes $messageType]
	if {$messageTypeID == -1} {
		return -code error "Invalid message type: $messageType"
	}

	array set messageInfo [::nano::protocol::create::${messageType} {*}$args]

	set messageInfo(extensions) [expr {$messageInfo(extensions) | (($messageInfo(blockType) << 8) & 0x0f00)}]

	switch -- $network {
		"main" {
			set packetMagic "RC"
		}
		"beta" {
			set packetMagic "RB"
		}
	}

	set message [binary format a2ccccs \
		$packetMagic \
		$versionMax \
		$versionUsing \
		$versionMin \
		$messageTypeID \
		$messageInfo(extensions) \
	]

	append message $messageInfo(data)

	return $message
}


proc ::nano::network::client {sock messageType args} {
	set configuredNetwork [dict get $::nano::node::configuration network]

	set message [::nano::protocol::create $configuredNetwork $messageType {*}$args]

	::nano::node::log "Sending message [binary encode hex $message] ([::nano::protocol::parse $message]) to socket $sock"

	catch {
		if {[dict get $sock "type"] eq "realtime"} {
			set sockInfo $sock
			set sock [dict get $sock "socket"]
		}
	}

	if {[info exists sockInfo]} {
		fconfigure $sock -remote [dict get $sockInfo "remote"]
	}

	chan configure $sock -translation binary -encoding binary

	puts -nonewline $sock $message
	flush $sock

	set responseCommand ::nano::protocol::parse::${messageType}_response
	set response ""
	if {[info command $responseCommand] ne ""} {
		set response [$responseCommand $sock {*}$args]
	}

	return $response
}

proc ::nano::node::bootstrap::TMP_LEDGER_ADDBLOCK {block} {
	set blockHash [::nano::block::dict::toHash $block -binary]
	set ::nano::node::bootstrap::TMP_LEDGER($blockHash) 1
}

proc ::nano::node::bootstrap::TMP_LEDGER_ADDBLOCKHASH {blockHash} {
	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	set ::nano::node::bootstrap::TMP_LEDGER($blockHash) 1
}

proc ::nano::node::bootstrap::TMP_LEDGER_CHECKBLOCKHASH {blockHash} {
	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	if {[info exists ::nano::node::bootstrap::TMP_LEDGER($blockHash)]} {
		return true
	}

	return false
}

proc ::nano::node::bootstrap::TMP_LEDGER_BLOCKHASHCOUNT {} {
	return [llength [array names ::nano::node::bootstrap::TMP_LEDGER]]
}

proc ::nano::node::bootstrap::lazy_peer {peerAddress peerPort} {
	incr ::nano::node::bootstrap::lazyPeerCount

	set peerString "$peerAddress $peerPort"

	set firstTime true
	while {[llength [array names ::nano::node::bootstrap::lazy_pullQueue]] != 0} {
		if {!$firstTime && ![info exists peerSock]} {
			incr ::nano::node::bootstrap::lazyPeerCount -1

			return
		}

		set blockHash [lindex [array names ::nano::node::bootstrap::lazy_pullQueue] 0]
		set blockHashString [string toupper [binary encode hex $blockHash]]

		if {[::nano::node::bootstrap::TMP_LEDGER_CHECKBLOCKHASH $blockHash]} {
			unset -nocomplain ::nano::node::bootstrap::lazy_pullQueue($blockHash)
			::nano::node::log "Skipping $blockHashString (already in local ledger -- this is okay, it just means we queued something but by the time it was acted on it was already fetched, so no work is needed)"

			# Avoid getting busy in this loop and monopolizing the thread
			# by yielding temporarily
			::nano::node::_sleep 0

			continue
		}

		if {$firstTime} {
			set firstTime false

			::nano::node::log "Connecting to $peerString"

			if {[catch {
				set peerSock [::nano::node::createSocket bootstrap $peerAddress $peerPort]
			}]} {
				::nano::node::log "Failed to connect to $peerString"

				incr ::nano::node::bootstrap::lazyPeerCount -1

				return
			}
		}

		::nano::node::log "Pulling $blockHashString from $peerString"

		unset -nocomplain chainAccount chainFrontier block
		set origBlockHash $blockHash
		set lastBlock ""
		set failedToDownload false

		if {[catch {
			set chainReachedEnd false
			::nano::network::client $peerSock bulk_pull $blockHash -count 128 -foreach {prevBlock {
				set isFinalBlock false
				if {$prevBlock eq ""} {
					set isFinalBlock true
				}

				# We don't start processing blocks until after we have pulled the second block
				# so that we have access to the next block in the download (which is the
				# previous block in the chain) to verify balance changes for state blocks
				set block $lastBlock
				set lastBlock $prevBlock
				if {$block eq ""} {
					continue
				}

				set blockType [dict get $block type]
				set blockHash [::nano::block::dict::toHash $block -binary]
				set blockHashString [string toupper [binary encode hex $blockHash]]

				# Remove this block from the pull queue
				unset -nocomplain ::nano::node::bootstrap::lazy_pullQueue($blockHash)

				# Get the frontier and account for this chain
				if {![info exists chainFrontier]} {
					set chainFrontier $blockHash
				}

				if {![info exists chainAccount]} {
					if {[dict exists $block "account"]} {
						set chainAccount [dict get $block "account"]
						set seenFrontiers($chainAccount) $chainFrontier
					}
				}

				# Determine if this block is a receiving block
				unset -nocomplain isReceive link
				if {$blockType in {open receive}} {
					set isReceive true
				}

				if {$blockType in {send change}} {
					set isReceive false
				}

				if {![info exists isReceive]} {
					if {$prevBlock eq ""} {
						if {$blockType eq "state"} {
							if {[dict get $block previous] eq $::nano::block::zero} {
								set isReceive true
							} else {
								set ::nano::node::bootstrap::lazy_pullQueue([binary decode hex [dict get $block previous]]) true
							}
						} else {
							error "Something is wrong.  There is no following block to this $blockType block"
						}
					}
				}

				if {![info exists isReceive]} {
					catch {
						if {[dict get $block balance] > [dict get $prevBlock balance]} {
							set isReceive true
						}
					}
				}

				if {![info exists isReceive]} {
					set isReceive false
				}

				# If so, find the source block hash
				if {$isReceive} {
					switch -- $blockType {
						"state" {
							set link [dict get $block link]
						}
						"open" - "receive" {
							set link [dict get $block source]
						}
						default {
							error "Unable to handle receiving from block type $blockType"
						}
					}

					set link [string toupper $link]
				}

				# Determine if this block is an open block
				set isOpen false
				if {$blockType eq "open"} {
					set isOpen true
				} elseif {$blockType eq "state" && [dict get $block previous] eq $::nano::block::zero} {
					set isOpen true
				}

				# If we reached the open block, declare victory
				if {$isOpen} {
					set chainReachedEnd true
				}

				# Determine if we already have this block
				set alreadyPulledLink false

				if {[::nano::node::bootstrap::TMP_LEDGER_CHECKBLOCKHASH $blockHash]} {
					set alreadyPulledThisBlock true
				} else {
					set alreadyPulledThisBlock false

					if {$isReceive && [::nano::node::bootstrap::TMP_LEDGER_CHECKBLOCKHASH $link]} {
						set alreadyPulledLink true
					}
				}

				::nano::node::bootstrap::TMP_LEDGER_ADDBLOCK $block

				set skippingText ""
				if {$alreadyPulledLink} {
					set skippingText " (skipped adding link)"
				}

				if {$alreadyPulledThisBlock} {
					set skippingText " (already have this block, thus the rest of this chain)"
				}

				if {$isReceive} {
					::nano::node::log "Pull got $blockHashString ($blockType) <- $link${skippingText}"

					if {!$alreadyPulledThisBlock && !$alreadyPulledLink} {
						set ::nano::node::bootstrap::lazy_pullQueue([binary decode hex $link]) true
					}
				} else {
					::nano::node::log "Pull got $blockHashString ($blockType)${skippingText}"
				}
			}}

			if {!$chainReachedEnd} {
				set previous [dict get $block previous]
				set ::nano::node::bootstrap::lazy_pullQueue([binary decode hex $previous]) true
			}
		} bulkPullError]} {
			set failedToDownload true
		}

		if {$failedToDownload} {
			::nano::node::log "Error: $bulkPullError"

			if {[info exists peerSock]} {
				::nano::node::closeSocket $peerSock
				unset peerSock
			}

			if {$lastBlock ne ""} {
				set blockHash [::nano::block::dict::toHash $block -binary]
			} else {
				set blockHash $origBlockHash
			}

			set ::nano::node::bootstrap::lazy_pullQueue($origBlockHash) true
		}
	}

	if {[info exists peerSock]} {
		::nano::node::closeSocket $peerSock
	}

	incr ::nano::node::bootstrap::lazyPeerCount -1
}

proc ::nano::node::bootstrap::peer {peer peerPort} {
	::nano::node::log "Connecting to ${peer}:${peerPort}"

	catch {
		set sock [::nano::network::_connect $peer $peerPort]
	} err
	if {![info exists sock]} {
		::nano::node::log "Failed to connect to ${peer} ${peerPort}: $::errorInfo"

		return
	}
	defer::defer close $sock

	::nano::node::log "Connected to $peer:$peerPort ;; sock = $sock"

	if {$::nano::node::bootstrap::frontier_req_running} {
		while true {
			if {[llength $::nano::node::bootstrap::frontiers_to_pull] == 0} {
				if {!$::nano::node::bootstrap::frontier_req_running} {
					break
				}

				::nano::node::_sleep 100 0

				continue
			}

			set accountInfo [lindex $::nano::node::bootstrap::frontiers_to_pull 0]
			set ::nano::node::bootstrap::frontiers_to_pull [lrange $::nano::node::bootstrap::frontiers_to_pull 1 end]

			set account [dict get $accountInfo "account"]

			::nano::node::log "Pulling $accountInfo"
			# XXX:TODO: Compare frontier, and supply our local one
			::nano::network::client $sock "bulk_pull" $account
			while true {
				::nano::network::_recv $sock 32
			}
		}
	} else {
		set ::nano::node::bootstrap::frontier_req_running true
		defer::defer set ::nano::node::bootstrap::frontier_req_running false

		::nano::node::log "Requesting frontiers"
		# XXX:TODO: Age?
		::nano::network::client $sock "frontier_req"
		while true {
			set account [::nano::address::fromPublicKey [::nano::network::_recv $sock 32]]
			set frontier [binary encode hex [::nano::network::_recv $sock 32]]

			lappend ::nano::node::bootstrap::frontiers_to_pull [dict create account $account frontier $frontier]
		}
	}

	return
}

proc ::nano::network::_dns::toIPList {name} {
	if {[::ip::version $name] > 0} {
		return [list $name]
	}

	set retval [list]
	foreach addressType {A AAAA} {
		set dnsQueryID [::dns::resolve $name -type $addressType]
		for {set dnsCheck 0} {$dnsCheck < 100} {incr dnsCheck} {
			switch -- [::dns::status $dnsQueryID] {
				"ok" {
					lappend retval {*}[::dns::address $dnsQueryID]

					break
				}
				"error" - "timeout" - "eof" {
					break
				}
				default {
				}
			}
			::nano::node::_sleep 10
		}
		::dns::cleanup $dnsQueryID
	}

	return $retval
}

# XXX:TODO: Which namespace should this go in ?
proc ::nano::node::_randomSortList {args} {
	set list [lindex $args end]
	set args [lrange $args 0 end-1]
	set salt [expr {rand()}]
	tailcall lsort {*}$args -command [list apply {{salt a b} {
		if {$a eq $b} {
			return 0
		}
		set a [binary encode hex [::nano::internal::hashData "${salt}|${a}"]]
		set b [binary encode hex [::nano::internal::hashData "${salt}|${b}"]]
		set a "0x${a}"
		set b "0x${b}"
		if {$a < $b} {
			return -1
		} else {
			return 1
		}
	}} $salt] $list
}

proc ::nano::node::bootstrap_lazy {startBlockHash} {
	if {[string length $startBlockHash] != $::nano::block::hashLength} {
		set startBlockHash [binary decode hex $startBlockHash]
	}

	set ::nano::node::bootstrap::lazy_pullQueue($startBlockHash) true

	if {[info exists ::nano::node::bootstrap::lazyRunning]} {
		return
	}
	set ::nano::node::bootstrap::lazyRunning true

	set ::nano::node::bootstrap::lazyPeerCount 0

	while {[llength [array names ::nano::node::bootstrap::lazy_pullQueue]] != 0 || $::nano::node::bootstrap::lazyPeerCount != 0} {
		set peerInfoList [::nano::node::getPeers]
		::nano::node::log "Have [llength $peerInfoList] peers"

		foreach peerInfo $peerInfoList {
			set peer     [dict get $peerInfo "address"]
			set peerPort [dict get $peerInfo "port"]

			if {[llength [info command ::nano::node::bootstrap::peer_*]] >= [dict get $::nano::node::configuration node bootstrap_connections]} {
				continue
			}

			set peerId [binary encode hex [::nano::internal::hashData "lazy:$peer:$peerPort" 5]]

			if {[info command ::nano::node::bootstrap::peer_${peerId}] ne ""} {
				continue
			}

			coroutine ::nano::node::bootstrap::peer_${peerId} ::nano::node::bootstrap::lazy_peer $peer $peerPort
		}

		::nano::node::_sleep 30000
	}

	unset ::nano::node::bootstrap::lazyRunning
}

proc ::nano::node::bootstrap {} {
	set ::nano::node::bootstrap::frontiers_to_pull [list]
	set ::nano::node::bootstrap::frontier_req_running false

	while true {
		set peerInfoList [::nano::node::getPeers]
		::nano::node::log "Have [llength $peerInfoList] peers"

		foreach peerInfo $peerInfoList {
			set peer     [dict get $peerInfo "address"]
			set peerPort [dict get $peerInfo "port"]

			if {[llength [info command ::nano::node::bootstrap::peer_*]] >= [dict get $::nano::node::configuration node bootstrap_connections]} {
				continue
			}

			set peerId [binary encode hex [::nano::internal::hashData "$peer:$peerPort" 5]]

			if {[info command ::nano::node::bootstrap::peer_${peerId}] ne ""} {
				continue
			}

			coroutine ::nano::node::bootstrap::peer_${peerId} ::nano::node::bootstrap::peer $peer $peerPort
		}

		::nano::node::_sleep 30000
	}
}

proc ::nano::network::_connect {host port} {
	if {[info coroutine] eq ""} {
		set sock [socket $host $port]
	} else {
		set sock [socket -async $host $port]
		chan event $sock writable [info coroutine]
		chan event $sock readable [info coroutine]

		if {![chan configure $sock -connecting]} {
			if {[chan configure $sock -error] ne ""} {
				close $sock

				return -code error "Socket error connecting to $host $port"
			}

			chan event $sock writable ""
			chan event $sock readable ""

			return $sock
		}

		::nano::node::log "Waiting in the event loop for socket $sock to become writable"
		yield

		chan event $sock writable ""
		chan event $sock readable ""

		if {[eof $sock] || (![chan configure $sock -connecting] && [chan configure $sock -error] ne "") || [chan configure $sock -connecting]} {
			close $sock

			return -code error "EOF from socket"
		}
	}

	chan configure $sock -blocking false -translation binary -encoding binary

	return $sock
}

proc ::nano::network::_recv {sock bytes} {
	if {[info coroutine] ne ""} {
		chan event $sock readable [info coroutine]
	} else {
		chan configure $sock -blocking true
	}

	set retBuffer ""

	while {$bytes > 0} {
		if {[info coroutine] ne ""} {
			yield
		}

		set buffer [read $sock $bytes]
		set bufferLen [string length $buffer]
		if {$bufferLen == 0} {
			set chanError [chan configure $sock -error]
			if {$chanError ne ""} {
				return -code error "Short read on socket $sock ($bytes bytes remaining): $chanError"
			}

			if {[chan eof $sock]} {
				return -code error "Short read on socket $sock ($bytes bytes remaining): EOF"
			}

			continue
		}

		incr bytes -$bufferLen
		append retBuffer $buffer
	}

	chan event $sock readable ""

	return $retBuffer
}

proc ::nano::node::_sleep {ms {verbose 1}} {
	if {$verbose} {
		::nano::node::log "Sleeping for $ms ms"
	}

	if {[info coroutine] eq ""} {
		after $ms
	} else {
		after $ms [info coroutine]
		yield
	}
}

proc ::nano::node::getPeers {} {
	if {[info exists ::nano::node::configuration]} {
		set peers [dict get $::nano::node::configuration node preconfigured_peers]
		set defaultPeerPort [dict get $::nano::node::configuration node peering_port]
	} else {
		return [list]
	}

	set completePeers [list]
	foreach peer $peers {
		catch {
			foreach peer [::nano::network::_dns::toIPList $peer] {
				lappend completePeers [dict create address $peer port $defaultPeerPort]
			}
		}
	}

	set now [clock seconds]
	# Cleanup nonces while we are here
	foreach {peerKey peerInfo} [array get ::nano::node::_node_id_nonces] {
		set lastSeen [dict get $peerInfo "lastSeen"]
		if {($now - $lastSeen) > (5 * 60)} {
			unset ::nano::node::_node_id_nonces($peerKey)
		}
	}

	# Come up with a list of peers that we have seen recently
	foreach {peerKeyInfo peerInfo} [array get ::nano::node::peers] {
		set lastSeen [dict get $peerInfo "lastSeen"]
		set address [dict get $peerKeyInfo "address"]
		set peerPort [dict get $peerKeyInfo "port"]
		set peerKey [dict create address $address port $peerPort]

		if {($now - $lastSeen) > (5 * 60)} {
#puts "Have not seen $peerKey in a while, dropping (now=$now, lastSeen=$lastSeen)"
			unset -nocomplain ::nano::node::peers($peerKeyInfo)
			unset -nocomplain ::nano::node::_node_id_nonces($peerKey)
			continue
		}

		lappend completePeers $peerKey
	}

	set retval [::nano::node::_randomSortList -unique $completePeers]

	return $retval
}

proc ::nano::protocol::parse::keepalive {extensions messageData} {
	set peers [list]
	while {$messageData ne ""} {
		# Parse an address and port pair
		set foundElements [binary scan $messageData H32s address port]
		if {$foundElements != 2} {
			break
		}

		# Remove the parsed portion
		set messageData [string range $messageData 18 end]

		# Convert the hex-notation to an IPv6 address
		set address [string trim [regsub -all {....} $address {&:}] ":"]
		set address [::ip::contract $address]
		if {[string match "::ffff:*" $address] && [llength [split $address :]] == 5} {
			# Convert IPv4 addresses to dotted quad notation
			set address [::ip::normalize $address]
			set address [split $address :]
			set address [join [lrange $address end-1 end] ""]
			set address [::ip::intToString 0x$address]
		}
		set port [expr {$port & 0xffff}]

		lappend peers [dict create "address" $address "port" $port]
	}

	if {$messageData ne ""} {
		return -code error "Invalid keepalive packet [binary encode hex $messageData]: Had extra bytes"
	}

	return [dict create "peers" $peers]
}

proc ::nano::network::server::keepalive {messageDict} {
	set now [clock seconds]

	set peers [dict get $messageDict "peers"]

	foreach peer $peers {
		set address [dict get $peer "address"]
		set port [dict get $peer "port"]

		# Canonicalize the peer name to a key
		set peer [dict create address $address port $port]

		# If this peer is not already known, contact them requesting a handshake
		if {![info exists ::nano::node::peers($peer)]} {
			if {![info exists ::nano::node::_node_id_nonces($peer)]} {
				set node_id_nonce [::nano::internal::randomBytes 32]
				set ::nano::node::_node_id_nonces($peer) [dict create query $node_id_nonce lastSeen $now]

				set peerSock [::nano::node::createSocket realtime $address $port]
#puts "Querying $peerSock with node_id_handshake (1)"
				::nano::network::client $peerSock "node_id_handshake" query -query $node_id_nonce
			}
		}
	}

	return ""
}

proc ::nano::protocol::parse::node_id_handshake {extensions messageData} {
	array set result [list]

	set flags [nano::protocol::extensions::get "node_id_handshake" $extensions]
	set result(flags) $flags

	if {"query" in $flags} {
		binary scan $messageData H64a* result(query) messageData
	}

	if {"response" in $flags} {
		binary scan $messageData H64H128 result(key) result(signature)
	}

	return [array get result]
}

proc ::nano::network::server::node_id_handshake {messageDict} {
	set retval ""

	if {"query" in [dict get $messageDict flags]} {
		set query [dict get $messageDict query]
		set retval [dict create "invoke_client" [list node_id_handshake response -query [binary decode hex $query]]]
	}

	if {"response" in [dict get $messageDict flags]} {
		set peerInfo [dict get $messageDict socket remote]
		set peerAddress [lindex $peerInfo 0]
		set peerPort [lindex $peerInfo 1]
		set peer [dict create address $peerAddress port $peerPort]

		# XXX:TODO: Verify the nonce
		if {![info exists ::nano::node::_node_id_nonces($peer)]} {
			return ""
		}
		set sentNonce $::nano::node::_node_id_nonces($peer)
		unset ::nano::node::_node_id_nonces($peer)

		# Add the peer to our list of peers
#puts "Got node_id_handshake response from $peer"
		set ::nano::node::peers($peer) [dict create lastSeen [clock seconds]]
	}

	return $retval
}

proc ::nano::network::server::confirm_ack {messageDict} {
	# keep statistics
	dict with messageDict {}

	incr ::nano::node::stats([list confirm_ack valid $valid])
	if {!$valid} {
		return ""
	}

	incr ::nano::node::stats([list confirm_ack rep $voteAccount valid $valid])

	incr ::nano::node::stats([list confirm_ack voteType $voteType])
	incr ::nano::node::stats([list confirm_ack rep $voteAccount voteType $voteType])

	if {![info exists ::nano::node::stats([list confirm_ack rep $voteAccount minVoteSequence])]} {
		set ::nano::node::stats([list confirm_ack rep $voteAccount minVoteSequence]) $voteSequence
	} else {
		if {$::nano::node::stats([list confirm_ack rep $voteAccount minVoteSequence]) > $voteSequence} {
			set ::nano::node::stats([list confirm_ack rep $voteAccount minVoteSequence]) $voteSequence
		}
	}

	if {![info exists ::nano::node::stats([list confirm_ack rep $voteAccount maxVoteSequence])]} {
		set ::nano::node::stats([list confirm_ack rep $voteAccount maxVoteSequence]) $voteSequence
	} else {
		if {$::nano::node::stats([list confirm_ack rep $voteAccount maxVoteSequence]) < $voteSequence} {
			set ::nano::node::stats([list confirm_ack rep $voteAccount maxVoteSequence]) $voteSequence
		}
	}

	set votedOn [llength $hashes]

	incr ::nano::node::stats([list confirm_ack votedOnCount]) $votedOn
	incr ::nano::node::stats([list confirm_ack rep $voteAccount votedOnCount]) $votedOn

	foreach hash $hashes {
		set ::nano::node::_stats_seen_hashes($hashes) 1
		set ::nano::node::_stats_seen_hashes_by_rep([list $voteAccount $hashes]) 1
	}

	set ::nano::node::stats([list confirm_ack votedOnUniqueCount]) [llength [array names ::nano::node::_stats_seen_hashes]]
	set ::nano::node::stats([list confirm_ack rep $voteAccount votedOnUniqueCount]) [llength [array names ::nano::node::_stats_seen_hashes_by_rep [list $voteAccount *]]]

	return ""
}

proc ::nano::protocol::parse::publish {extensions messageData} {
	set blockTypeID [expr {($extensions >> 8) & 0x0f}]
	set blockType [::nano::block::typeFromTypeID $blockTypeID]
	set blockDict [::nano::block::dict::fromBlock $messageData -type=$blockType]
	set blockHash [::nano::block::dict::toHash $blockDict -hex]

	# XXX:TEMPORARY
	dict unset blockDict _blockData
	dict unset blockDict _workData

	set retval(blockType) $blockType
	set retval(block) $blockDict
	set retval(hash) $blockHash

	return [array get retval]
}

proc ::nano::network::server::publish {messageDict} {
	#puts "block: [binary encode hex $blockData]"
#9e1272edade3c247c738a4bd303eb0cfc3da298444bb9d13b8ffbced34ff036f4e1ff833324efc81c237776242928ef76a2cdfaa53f4c4530ee39bfff1977e26e382dd09ec8cafc2427cf817e9afe1f372ce81085ab4feb1f3de1f25ee818e5d000000008fc492fd20e57d048e000000204e7a62f25df739eaa224d403cb107b3f9caa0280113b0328fad3b402c465169006f988549a8b1e20e0a09b4b4dcae5397f6fcc4d507675f58c2b29ae02341b0a4fe562201a61bf27481aa4567c287136b4fd26b4840c93c42c7d1f5c518503d68ec561af4b8cf8
#9e1272edade3c247c738a4bd303eb0cfc3da298444bb9d13b8ffbced34ff036fa5e3647d3d296ec72baea013ba7fa1bf5c3357c33c90196f078ba091295e6e03e382dd09ec8cafc2427cf817e9afe1f372ce81085ab4feb1f3de1f25ee818e5d000000008fb2604ebd1fe098b8000000204e7a62f25df739eaa224d403cb107b3f9caa0280113b0328fad3b402c465165287cd9c61752dc9d011f666534dbdc10461e927503f9599791d73b1cca7fdc032d76db3f91e5b5c3d6206fa48b01bd08da4a89f2e880242e9917cfc3db80d0b9bfe8e6d1dd183d5
	return ""
}

# Namespace ::nano::protocol::parse deals with the network level protocol (outside the node)
# Namespace ::nano::network::server deals with the node's actual interaction with the network
proc ::nano::protocol::parse {message} {
	set messageParsed [binary scan $message a2ccccsa* \
		result(packetMagic) \
		result(versionMax) \
		result(versionUsing) \
		result(versionMin) \
		result(messageTypeID) \
		result(extensions) \
		newBlockData
	]

	if {![info exists newBlockData]} {
		return ""
	}
	set blockData $newBlockData

	if {![info exists result(packetMagic)] || ![info exists result(messageTypeID)] || ![info exists result(extensions)]} {
		return ""
	}

	switch -- $result(packetMagic) {
		"RC" {
			set result(network) "main"
		}
		"RB" {
			set result(network) "beta"
		}
		default {
			return ""
		}
	}

	set result(messageType) [lindex $::nano::network::messageTypes $result(messageTypeID)]

	if {[catch {
		set result(messageDict) [::nano::protocol::parse::$result(messageType) $result(extensions) $blockData]
	} err]} {
		if {![string match "invalid command name *" $err]} {
			::nano::node::log "Error parsing $result(messageType): $err"
		}
	}

	return [array get result]
}

proc ::nano::network::server {message {networkType "bootstrap"} {peerSock ""}} {
	set messageData [::nano::protocol::parse $message]
	dict with messageData {}

	if {![info exists messageTypeID]} {
		::nano::node::log "*** Incoming: INVALID [binary encode hex $message] ($messageData)"

		return ""
	}

	::nano::node::log "*** Incoming: $messageType ($messageTypeID on $networkType; from $peerSock) [binary encode hex $message] ($messageData)"

	if {![info exists messageDict]} {
		return ""
	}

	set configuredNetwork [dict get $::nano::node::configuration network]
	if {$network ne $configuredNetwork} {
		return ""
	}

	dict set messageDict socket $peerSock

	set retval [dict create]
	if {[catch {
		set retval [::nano::network::server::${messageType} $messageDict]
	} err]} {
		if {![string match "invalid command name *" $err]} {
			::nano::node::log "Error handling ${messageType}: $err"
		}
	}

	return $retval
}

proc ::nano::node::closeSocket {peerSock} {
	if {[catch {
		if {[dict get $peerSock "type"] eq "realtime"} {
			# XXX:TODO: Probably don't close this socket
			set socket [dict get $peerSock "socket"]
		}
	}]} {
		set socket $peerSock
	}

	close $socket
}

proc ::nano::node::createSocket {type address port} {
	if {$type eq "realtime"} {
		# Determine our listening port
		set peeringPort [dict get $::nano::node::configuration node peering_port]

		# Start a UDP listening socket
		foreach protocolVersion {v4 v6} {
			if {[info exists ::nano::node::realtime::socket($protocolVersion)]} {
				continue
			}

			set flags [list]
			if {$protocolVersion eq "v6"} {
				lappend flags ipv6
			}

			set protocolSocket [udp_open $peeringPort {*}$flags reuse]
			set ::nano::node::realtime::socket($protocolVersion) $protocolSocket
			fconfigure $protocolSocket -blocking false -encoding binary -translation binary
			chan event $protocolSocket readable [list ::nano::node::realtime::incoming $protocolSocket]
		}

		# Used to just start listening
		if {$address eq "" || $port eq ""} {
			return
		}

		set protocolVersion "v[::ip::version $address]"
		set socket $::nano::node::realtime::socket($protocolVersion)
		set peerSock [list type "realtime" remote [list $address $port] socket $socket]
	} elseif {$type eq "bootstrap"} {
		set peerSock [::nano::network::_connect $address $port]
	} else {
		return -code error "Unknown network type: $type"
	}

	return $peerSock
}

proc ::nano::node::realtime::incoming {socket} {
	set data [read $socket 8192]
	if {$data eq ""} {
		return
	}

	set remote [chan configure $socket -peer]
	set address [lindex $remote 0]
	set port [lindex $remote 1]
	set peerSock [::nano::node::createSocket realtime $address $port]
	set response [::nano::network::server $data "realtime" $peerSock]
	if {$response eq ""} {
		return
	}

	set response [dict get $response "invoke_client"]

	::nano::network::client $peerSock {*}$response

	return
}

proc ::nano::node::realtime {} {
	package require udp

	set clientIDPrivateKey [dict get $::nano::node::configuration node client_id_private_key]

	# Start listening
	::nano::node::createSocket realtime "" ""

	# Periodically send keepalives to all known peers
	while true {
		set allPeers [::nano::node::getPeers]
		set peers [lrange $allPeers 0 15]

		# XXX:TODO: Make this a configuration option
		set superPeer true

		if {$superPeer} {
			set contactPeers $allPeers
		} else {
			set peerNotifyCount [expr {int(sqrt([llength $allPeers]))}]
			if {$peerNotifyCount < 16} {
				set peerNotifyCount 16
			}
			if {$peerNotifyCount > 128} {
				set peerNotifyCount 128
			}

			set contactPeers [lrange $allPeers 0 $peerNotifyCount]
		}

		foreach peerInfo $contactPeers {
			set peerAddress [dict get $peerInfo "address"]
			set peerPort [dict get $peerInfo "port"]

			set peerSock [::nano::node::createSocket realtime $peerAddress $peerPort]

			set node_id_nonce [::nano::internal::randomBytes 32]

			::nano::network::client $peerSock keepalive $peers -local true
#puts "Querying $peerSock with node_id_handshake (2)"
			::nano::network::client $peerSock node_id_handshake query -query $node_id_nonce
		}

		::nano::node::_sleep [expr {1 * 60 * 1000}]
	}
}

proc ::nano::node::start args {
	package require defer
	package require udp

	set ::nano::node::startTime [clock seconds]
	set ::nano::node::statsStartTime [clock seconds]

	array set config {
		-bootstrap true
		-realtime true
		-wait true
	}
	array set config $args

	if {$config(-bootstrap)} {
		coroutine ::nano::node::bootstrap::run ::nano::node::bootstrap
	}

	if {$config(-realtime)} {
		coroutine ::nano::node::realtime::run ::nano::node::realtime
	}

	if {$config(-wait)} {
		vwait ::nano::node::_FOREVER_
	}
}

# RPC Client
## Side-effect: Sets ::nano::rpc::client::config
proc ::nano::rpc::client::init args {
	if {![info exists ::nano::rpc::client::config]} {
		set ::nano::rpc::client::config [dict create \
		    url "http://localhost:7076/" \
		]
	}

	if {[llength $args] > 0} {
		set ::nano::rpc::client::config [dict merge $::nano::rpc::client::config $args]
	}

	return true
}

proc ::nano::rpc::client {action args} {
	::nano::rpc::client::init

	set rpcURL [dict get $::nano::rpc::client::config "url"]

	set jsonArgs [list]
	foreach {key value} $args {
		switch -exact -- $key {
			"-count" {}
			"-accounts" {
				set valueAsStrings [lmap valueItem $value { json::write string $valueItem }]
				set value [json::write array {*}$valueAsStrings]
			}
			default {
				set value [json::write string $value]
			}
		}
		set key [string range $key 1 end]

		lappend jsonArgs $key $value
	}

	set query [json::write object action [json::write string $action] {*}$jsonArgs]

	catch {
		set token [http::geturl $rpcURL -query $query]
		set ncode [http::ncode $token]
		set data [http::data $token]
	} error
	if {![info exists data]} {
		set ncode -1
		set data $error
	}

	if {[info exists token]} {
		http::cleanup $token
	}

	if {$ncode ne "200"} {
		return -code error "$ncode: $data"
	}

	set data [json::json2dict $data]

	return $data
}

# Account balance manipulation
proc ::nano::balance::toUnit {raw toUnit {decimals 0}} {
	set divisor [dict get $::nano::balance::_conversion $toUnit]

	if {$decimals == 0} {
		set balance [expr {entier(($raw / ($divisor * 1.0)) + 0.5)}]
	} else {
		set balance [expr {$raw / ($divisor * 1.0)}]
		set balance [format "%.${decimals}f" $balance]
	}

	return $balance
}

proc ::nano::balance::toRaw {balance fromUnit} {
	set multiplier [dict get $::nano::balance::_conversion $fromUnit]

	# Determine how long the multiplier is
	set zeros [expr {entier(log10($multiplier))}]

	# Find the location of the decimal point (or add it)
	set decimal [string first "." $balance]
	if {$decimal == -1} {
		append balance "."

		set decimal [string first "." $balance]
	}

	# Ensure that the balance has atleast the right number of trailing zeros
	append balance [string repeat "0" $zeros]

	# Remove the decimal point
	set balance [string replace $balance $decimal $decimal]

	# Get the subset of the string that corresponds to the balance
	set balance [string range $balance 0 [expr {$zeros + $decimal - 1}]]

	# Convert to a integer type
	set balance [expr {entier($balance)}]

	return $balance
}

proc ::nano::balance::normalizeUnitName {unit} {
	set multiplier [dict get $::nano::balance::_conversion $unit]
	foreach {unitName multiplierCheck} $::nano::balance::_conversion {
		if {$multiplierCheck == $multiplier} {
			return $unitName
		}
	}
}

proc ::nano::balance::toHuman {raw {decimals 3}} {
	set humanUnit [normalizeUnitName _USER]
	set humanUnitMultiplier [dict get $::nano::balance::_conversion $humanUnit]

	if {$raw > [expr {$humanUnitMultiplier / 10000000}]} {
		set baseUnit $humanUnit
	} else {
		set baseUnit "raw"
	}

	set balance [toUnit $raw $baseUnit $decimals]
	set work [split $balance "."]
	set leading  [lindex $work 0]
	set trailing [string trimright [lindex $work 1] "0"]
	set balance [join [list $leading $trailing] "."]
	set balance [string trimright $balance "."]

	set result [list $balance $baseUnit]

	return $result
}

proc ::nano::node::cli args {
	switch -exact -- [lindex $args 0] {
		"-interactive" {
			set ::nano::node::cli::_using_repl true

			::nano::node::cli -import

			set use_tclreadline false
			catch {
				package require tclreadline
				set use_tclreadline true
			}

			if {$use_tclreadline} {
				proc ::tclreadline::prompt1 {} {
					return "\[[dict get $::nano::node::configuration network]\] nano-node [package present nano]> "
				}
				::tclreadline::Loop
			} else {
				fconfigure stdout -blocking false
				puts -nonewline "> "
				flush stdout
				fileevent stdin readable [list apply {{} {
					uplevel #0 {
						gets stdin __line__
						if {$__line__ eq "" && [eof stdin]} {
							exit 0
						}

						if {[catch $__line__ __result__]} {
							puts "\[ERROR\] $::errorInfo"
						} else {
							if {$__result__ ne ""} {
								puts "$__result__"
							}
						}
					}

					puts -nonewline "> "
					flush stdout
				}}]

				vwait forever
			}
		}
		"-import" {
			uplevel #0 {
				namespace import ::nano::node::cli::*
			}
		}
		default {
			error "Not implemented"
		}
	}

}

proc ::nano::node::cli::_interval {interval} {
	set response [list]
	foreach {divisor unit} {60 seconds 60 minutes 24 hours 36527 days 1 century} {
		set amount [expr {$interval % $divisor}]
		if {$amount > 0} {
			if {$amount == 1} {
				set unit [string range $unit 0 end-1]
			}

			lappend response $unit $amount
		}
		set interval [expr {$interval / $divisor}]
	}

	return "[lreverse $response]"
}

proc ::nano::node::cli::uptime {} {
	set now [clock seconds]
	set start $::nano::node::startTime
	set statsStart $::nano::node::statsStartTime

	set uptime [expr {$now - $start}]
	set uptimeStats [expr {$now - $statsStart}]

	set format {%-19s: %s}
	lappend response [format $format Uptime [_interval $uptime]]
	lappend response [format $format "Stats last cleared" "[_interval $uptimeStats] ago"]

	return [join $response "\n"]
}

proc ::nano::node::cli::stats args {
	if {[lindex $args 0] eq "-clear"} {
		set ::nano::node::statsStartTime [clock seconds]

		unset -nocomplain ::nano::node::stats
		unset -nocomplain ::nano::node::_stats_seen_hashes
		unset -nocomplain ::nano::node::_stats_seen_hashes_by_rep

		return
	}

	set globalOnly false
	if {[lindex $args 0] eq "-global"} {
		set globalOnly true
	}

	if {[lindex $args 0] in {"-rep" "-representative"}} {
		set repOnly [::nano::address::toPublicKey [lindex $args 1] -binary]
	}

	set maxKeyLen 0
	foreach {key val} [array get ::nano::node::stats] {
		if {[lindex $key 1] eq "rep"} {
			if {$globalOnly} {
				continue
			} elseif {[info exists repOnly]} {
				if {$repOnly ne [::nano::address::toPublicKey [lindex $key 2] -binary]} {
					continue
				}
				set key [concat [lrange $key 0 0] [lrange $key 3 end]]
			}
		} else {
			if {[info exists repOnly]} {
				continue
			}
		}

		set keyLen [string length $key]
		if {$keyLen > $maxKeyLen} {
			set maxKeyLen $keyLen
		}

		set localStats($key) $val
	}

	foreach {key val} [lsort -stride 2 -dictionary [array get localStats]] {
		puts [format "%-${maxKeyLen}s = $val" $key $val]
	}

	return
}

proc ::nano::node::cli::version {} {
	return [package present nano]
}

proc ::nano::node::cli::help args {
	set response [list]
	if {[llength $args] == 0} {
		lappend response "Commands:"

		foreach command [lsort -dictionary [info command ::nano::node::cli::*]] {
			set command [namespace tail $command]
			if {[string match "_*" $command]} {
				continue
			}

			set description ""
			lappend response [format "   %-12s - %s" $command $description]
		}
	}

	return [join $response "\n"]
}

proc ::nano::node::cli::network {} {
	return [dict get $::nano::node::configuration network]
}

proc ::nano::node::cli::config args {
	set config $::nano::node::configuration
	dict set config node client_id_private_key [binary encode hex [dict get $config node client_id_private_key]]
	set subtreePrefix [lrange $args 0 end-1]
	set subtreeKey [lindex $args end]
	set subtreePrefixConfig [join $subtreePrefix /]
	if {$subtreePrefixConfig ne ""} {
		append subtreePrefixConfig "/"
	}

	set subtree [dict get $config {*}$subtreePrefix]

	set json [::nano::node::_configDictToJSON $subtree $subtreePrefixConfig $subtreeKey]

	return $json
}

proc ::nano::node::cli::peers args {
	if {[lindex $args 0] eq "-count"} {
		return [llength [::nano::node::getPeers]]
	}

	if {[llength $args] == 1} {
		set glob [lindex $args 0]
		if {[string index $glob 0] eq "!"} {
			set globInvert true
			set glob [string range $glob 1 end]
		} else {
			set globInvert false
		}
	}

	lappend response "Peers:"

	set now [clock seconds]
	foreach peer [::nano::node::getPeers] {
		if {[info exists glob]} {
			if {![string match $glob $peer] == !$globInvert} {
				continue
			}
		}

		if {[info exists ::nano::node::peers($peer)]} {
			set peerInfo $::nano::node::peers($peer)
			set lastSeen [dict get $peerInfo lastSeen]

			set delta [expr {$now - $lastSeen}]

			set age "last seen $delta seconds ago"
		} else {
			set age "statically configured peer"
		}

		lappend response "  $peer: $age"
	}
	return [join $response "\n"]
}

proc ::nano::node::cli::_pull_chain {startBlockHash {endBlockHash "genesis"}} {
	if {$endBlockHash eq "genesis"} {
		set network [dict get $::nano::node::configuration network]
		set endBlockHash [::nano::block::dict::toHash [::nano::block::dict::genesis $network] -hex]
	}

	set startBlockHash [binary decode hex $startBlockHash]
	set endBlockHash [binary decode hex $endBlockHash]

	if {[string length $startBlockHash] != $::nano::block::hashLength} {
		error "Invalid start block hash specified"
	}

	if {[string length $endBlockHash] != $::nano::block::hashLength} {
		error "Invalid end block hash specified"
	}

	set startBlockHash [string toupper [binary encode hex $startBlockHash]]
	set endBlockHash [string toupper [binary encode hex $endBlockHash]]

	::nano::node::bootstrap::TMP_LEDGER_ADDBLOCKHASH $endBlockHash

	puts "Pulling $startBlockHash to $endBlockHash"

	set startTime [clock seconds]
	coroutine ::nano::node::bootstrap::runLazy ::nano::node::bootstrap_lazy $startBlockHash
	if {![info exists ::nano::node::bootstrap::lazyRunning]} {
		vwait ::nano::node::bootstrap::lazyRunning
	}
	vwait ::nano::node::bootstrap::lazyRunning
	set endTime [clock seconds]

	set blocksPulled [::nano::node::bootstrap::TMP_LEDGER_BLOCKHASHCOUNT]
	set delta [expr {$endTime - $startTime}]

	puts "Pulled $blocksPulled blocks in [::nano::node::cli::_interval $delta]"
}

namespace eval ::nano::node::cli {
	namespace export -clear *
}

if {[info exists ::nano::node::cli::_using_repl]} {
	::nano::node::cli -import
}
