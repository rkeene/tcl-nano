#! /usr/bin/env tclsh

package require json
package require json::write

namespace eval ::nano {}
namespace eval ::nano::address {}
namespace eval ::nano::key {}
namespace eval ::nano::block {}
namespace eval ::nano::block::create {}
namespace eval ::nano::account {}

set ::nano::block::hashLength 32
set ::nano::block::signatureLength 64
set ::nano::key::publicKeyLength 32
set ::nano::key::privateKeyLength 32
set ::nano::key::seedLength 32

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
		if {[string length $pubKey] == $::nano::key::publicKeyLength} {
			set inputFormat "bytes"
		} else {
			set inputFormat "hex"
		}
	}

	if {$inputFormat eq "hex"} {
		set pubKey [binary decode hex $pubKey]
	}

	if {[string length $pubKey] != $::nano::key::publicKeyLength} {
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

proc ::nano::address::fromPrivateKey {key args} {
	set pubKey [::nano::key::publicKeyFromPrivateKey $key]
	tailcall ::nano::address::fromPublicKey $pubKey {*}$args
}

proc ::nano::key::generateNewSeed {} {
	tailcall ::nano::internal::generateSeed
}

proc ::nano::key::generateNewKey {} {
	tailcall ::nano::internal::generateKey
}

proc ::nano::key::computeKey {seed args} {
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

proc ::nano::key::publicKeyFromPrivateKey {key args} {
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

	if {[string length $key] != $::nano::key::privateKeyLength} {
		set key [binary decode hex $key]
	}

	set pubKey [::nano::internal::publicKey $key]
	if {$outputFormat eq "hex"} {
		set pubKey [string toupper [binary encode hex $pubKey]]
	}

	return $pubKey
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

proc ::nano::block::signBlockHash {blockHash key args} {
	set outputFormat "bytes"
	foreach arg $args {
		switch -exact -- $arg {
			"-hex" {
				set outputFormat "hex"
			}
			"-binary" {
				set outputFormat "bytes"
			}
		}
	}

	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	if {[string length $key] != $::nano::key::privateKeyLength} {
		set key [binary decode hex $key]
	}

	set signature [::nano::internal::signDetached $blockHash $key]

	if {$outputFormat eq "hex"} {
		set signature [string toupper [binary encode hex $signature]]
	}

	return $signature
}

proc ::nano::block::signBlock {blockData args} {
	set blockHash [::nano::block::hash $blockData]

	tailcall ::nano::block::signBlockHash $blockHash {*}$args
}

proc ::nano::block::signBlockJSON {blockJSON args} {
	set blockData [::nano::block::fromJSON $blockJSON]

	tailcall ::nano::block::signBlock $blockData {*}$args
}

proc ::nano::block::verifyBlockHash {blockHash signature pubKey} {
	if {[string length $blockHash] != $::nano::block::hashLength} {
		set blockHash [binary decode hex $blockHash]
	}

	if {[string length $signature] != $::nano::block::signatureLength} {
		set signature [binary decode hex $signature]
	}

	if {[string length $pubKey] != $::nano::key::publicKeyLength} {
		set key [binary decode hex $pubKey]
	}

	set valid [::nano::internal::verifyDetached $blockHash $signature $pubKey]

	return $valid
}

proc ::nano::block::verifyBlock {blockData args} {
	set blockHash [::nano::block::hash $blockData]

	tailcall ::nano::block::verifyBlockHash $blockHash {*}$args
}

proc ::nano::block::verifyBlockJSON {blockJSON args} {
	set blockData [::nano::block::fromJSON $blockJSON]

	tailcall ::nano::block::verifyBlock $blockData {*}$args
}

proc ::nano::block::_dictToJSON {blockDict} {
	array set block $blockDict

	if {[info exists block(signKey)] && ([info exists block(_blockData)] || [info exists block(_blockHash)])} {
		if {![info exists block(_blockHash)]} {
			set block(_blockHash) [binary encode hex [::nano::block::hash $block(_blockData)]]
		}

		set block(signature) [::nano::block::signBlockHash $block(_blockHash) $block(signKey) -hex]
	}

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
		link link_as_account _blockHash _workHash signature
	}

	set blockJSONEntries [lmap field $blockJSONFields {
		if {![info exists block($field)]} {
			continue
		}

		switch -exact -- $field {
			"source" - "previous" - "link" - "_blockHash" - "_workHash" {
				set block($field) [string toupper $block($field)]
			}
		}
		return -level 0 [list $field [json::write string $block($field)]]
	}]
	set blockJSONEntries [join $blockJSONEntries]

	set blockJSON [json::write object {*}$blockJSONEntries]

	return $blockJSON
}

proc ::nano::block::toDict {blockData args} {
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

	set block(_blockData) $blockData

	return [array get block]
}

proc ::nano::block::toJSON {blockData args} {
	set blockDict [::nano::block::toDict $blockData {*}$args]

	set blockJSON [_dictToJSON $blockDict]

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

	set hash [::nano::internal::hashData $blockData $::nano::block::hashLength]

	if {$outputFormat eq "hex"} {
		set hash [string toupper [binary encode hex $hash]]
	}

	return $hash
}

proc ::nano::block::jsonFromDict {blockDict} {
	set blockJSON [::nano::block::_dictToJSON $blockDict]
	set block [::nano::block::fromJSON $blockJSON]
	set blockHash [::nano::block::hash $block]

	dict set blockDict "_blockHash" [binary encode hex $blockHash]

	set blockJSON [::nano::block::_dictToJSON $blockDict]

	return $blockJSON
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
		"_workHash" $block(previous) \
	]

	if {[info exists block(signKey)]} {
		dict set blockDict signKey $block(signKey)
	}

	tailcall ::nano::block::jsonFromDict $blockDict
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
		set block(previous) "0000000000000000000000000000000000000000000000000000000000000000"
		set block(previousBalance) 0
		set block(_workHash) [::nano::address::toPublicKey $block(to) -hex]
	} else {
		set block(_workHash) $block(previous)
	}

	set block(balance) [expr {$block(previousBalance) + $block(amount)}]

	set blockDict [dict create \
		"type" state \
		"account" $block(to) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link" $block(sourceBlock) \
		"_workHash" $block(_workHash) \
	]

	if {[info exists block(signKey)]} {
		dict set blockDict signKey $block(signKey)
	}

	tailcall ::nano::block::jsonFromDict $blockDict
}

# Usage:
#   setRepresentative account <account> previous <previousBlockHash>
#                     representative <newRepresentative> balance <balance>
proc ::nano::block::create::setRepresentative {args} {
	array set block $args

	set block(link) "0000000000000000000000000000000000000000000000000000000000000000"

	set blockDict [dict create \
		"type" state \
		"account" $block(account) \
		"previous" $block(previous) \
		"representative" $block(representative) \
		"balance" $block(balance) \
		"link" $block(link) \
		"_workHash" $block(previous) \
	]

	if {[info exists block(signKey)]} {
		dict set blockDict signKey $block(signKey)
	}

	tailcall ::nano::block::jsonFromDict $blockDict
}

# -- Tracked accounts --
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

	set ::nano::account::pending([list $accountPubKey $blockHash]) [dict create amount $amount]
}

proc ::nano::account::receive {account blockHash signKey} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	set frontierInfo [getFrontier $account]
	dict with frontierInfo {}

	set blockInfo $::nano::account::pending([list $accountPubKey $blockHash])
	unset ::nano::account::pending([list $accountPubKey $blockHash])

	set amount [dict get $blockInfo amount]
	set blockArgs [list to $account previousBalance $balance \
	                    amount $amount sourceBlock $blockHash \
	                    signKey $signKey representative $representative]

	if {[info exists frontierHash]} {
		lappend blockArgs previous $frontierHash
	}

	set block [::nano::block::create::receive {*}$blockArgs]

	set newFrontierHash [dict get [json::json2dict $block] "_blockHash"]
	set balance [expr {$balance + $amount}]

	setFrontier $account $newFrontierHash $balance $representative

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
		signKey         $signKey
	]

	set newBalance [expr {$fromBalance - $amount}]
	set newFrontierHash [dict get [json::json2dict $block] "_blockHash"]

	setFrontier $fromAccount $newFrontierHash $newBalance $fromRepresentative
	addPending  $toAccount $newFrontierHash $amount

	return $block
}

proc ::nano::account::receiveAllPending {key} {
	set outBlocks [list]

	set accountPubKey [::nano::key::publicKeyFromPrivateKey $key -hex]

	set signKey [binary encode hex $key]
	set account [::nano::address::fromPublicKey $accountPubKey]

	foreach accountPubKeyBlockHash [array names ::nano::account::pending [list $accountPubKey *]] {
		set blockHash [lindex $accountPubKeyBlockHash 1]
		lappend outBlocks [receive $account $blockHash $signKey]
	}

	return $outBlocks
}

package provide nano 0
