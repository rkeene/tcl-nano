#! /usr/bin/env tclsh

package require json
package require json::write

namespace eval ::nano {}
namespace eval ::nano::block {}
namespace eval ::nano::block::account {}
namespace eval ::nano::address {}

set ::nano::address::base32alphabet {13456789abcdefghijkmnopqrstuwxyz}
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

proc ::nano::address::fromPublicKey {pubKey args} {
	set addressPrefix "nano_"
	foreach arg $args {
		switch -exact -- $arg {
			"-xrb" {
				set addressPrefix "xrb_"
			}
			"-nano" {
				set addressPrefix "nano_"
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

	if {![info exists inputFormat]} {
		if {[string length $pubKey] == 32} {
			set inputFormat "bytes"
		} else {
			set inputFormat "hex"
		}
	}

	if {$inputFormat eq "hex"} {
		set pubKey [binary decode hex $pubKey]
	}

	if {[string length $pubKey] != 32} {
		return -code error "Invalid key (length)"
	}

	set checksum [string reverse [::nano::internal::hashData $pubKey 5]]
	append pubKey $checksum

	set pubKey [binary encode hex $pubKey]
	set pubKey [expr "0x$pubKey"]
	set alphabet [split $::nano::address::base32alphabet ""]
	set address ""
	for {set index 0} {$index < 60} {incr index} {
		set fiveBits [expr {$pubKey & 0x1F}]
		set pubKey [expr {$pubKey >> 5}]
		set byte [lindex $alphabet $fiveBits]
		append address $byte
	}
	set address [string reverse $address]
	set address "${addressPrefix}${address}"

	return $address
}

proc ::nano::block::fromJSON {json} {
	array set block [json::json2dict $json]

	switch -- $block(type) {
		"state" {
			# XXX:TODO: Find the source of this
			append blockData [binary decode hex "0000000000000000000000000000000000000000000000000000000000000006"]
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

proc ::nano::block::_dictToJSON {blockDict {addArgs_fromPublicKey ""}} {
	array set block $blockDict

	set blockJSONFields {type account source destination previous representative balance link link_as_account _blockHash}
	set blockJSONEntries [lmap field $blockJSONFields {
		if {![info exists block($field)]} {
			continue
		}

		switch -exact -- $field {
			"source" - "previous" - "link" - "_blockHash" {
				set block($field) [string toupper $block($field)]
			}
		}
		return -level 0 [list $field [json::write string $block($field)]]
	}]
	set blockJSONEntries [join $blockJSONEntries]

	set blockJSON [json::write object {*}$blockJSONEntries]

	return $blockJSON
}

proc ::nano::block::toJSON {blockData args} {
	set block(type) ""
	set addressPrefix "nano_"
	foreach arg $args {
		switch -glob -- $arg {
			"-type=*" {
				set block(type) [lindex [split $arg =] 1]
			}
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

	if {$block(type) eq ""} {
		switch -- [string length $blockData] {
			176 { set block(type) state   }
			96  { set block(type) open    }
			80  { set block(type) send    }
			default {
				return -code error "Unable to parse block, must specify type"
			}
		}
	}

	set addArgs_fromPublicKey [list]
	if {$addressPrefix eq "xrb_"} {
		lappend addArgs_fromPublicKey "-xrb"
	}

	switch -- $block(type) {
		"state" {
			binary scan $blockData H64a32H64a32H32H64 \
				block(header) \
				block(account) \
				block(previous) \
				block(representative) \
				block(balance) \
				block(link)

			if {$block(header) ne "0000000000000000000000000000000000000000000000000000000000000006"} {
				return -code error "Invalid block"
			}
		}
		"open" {
			binary scan $blockData H64a32a32 \
				block(source) \
				block(representative) \
				block(account)
		}
		"send" {
			binary scan $blockData H64a32H32 \
				block(previous) \
				block(destination) \
				block(balance)
		}
		"receive" {
			binary scan $blockData H64H64 \
				block(previous) \
				block(source)
		}
		"change" {
			binary scan $blockData H64a32 \
				block(previous) \
				block(representative)
		}
		default {
			return -code error "Invalid block type: $block(type)"
		}
	}

	foreach field {account representative link_as_account destination balance} {
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

	set blockJSON [_dictToJSON [array get block] ${addArgs_fromPublicKey}]

	return $blockJSON
}

proc ::nano::block::hash {blockData args} {
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

	set hash [::nano::internal::hashData $blockData 32]

	if {$outputFormat eq "hex"} {
		set hash [string toupper [binary encode hex $hash]]
	}

	return $hash
}

proc ::nano::block::account::_finalizeBlock {blockDict} {
	set blockJSON [::nano::block::_dictToJSON $blockDict]
	set block [::nano::block::fromJSON $blockJSON]
	set blockHash [::nano::block::hash $block -hex]
	dict set blockDict "_blockHash" $blockHash
	set blockJSON [::nano::block::_dictToJSON $blockDict]
	return $blockJSON
}

proc ::nano::block::account::send {args} {
	array set block $args
	if {![info exists block(representative)]} {
		set block(representative) $block(from)
	}

	set block(balance) [expr {$block(priorBalance) - $block(amount)}]

	set blockDict [dict create \
		"type" state \
		"account" $block(from) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link_as_account" $block(to) \
	]

	tailcall _finalizeBlock $blockDict
}

proc ::nano::block::account::receive {args} {
	array set block $args
	if {![info exists block(representative)]} {
		set block(representative) $block(to)
	}

	if {![info exists block(previous)]} {
		set block(previous) "0000000000000000000000000000000000000000000000000000000000000000"
	}

	set block(balance) [expr {$block(priorBalance) + $block(amount)}]

	set blockDict [dict create \
		"type" state \
		"account" $block(to) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link" $block(sourceBlock) \
	]

	tailcall _finalizeBlock $blockDict
}

proc ::nano::block::account::setRepresentative {args} {
	array set block $args

	set block(balance) $block(priorBalance)
	set block(link) "0000000000000000000000000000000000000000000000000000000000000000"

	set blockDict [dict create \
		"type" state \
		"account" $block(account) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link" $block(link) \
	]

	tailcall _finalizeBlock $blockDict
}


package provide nano 0
