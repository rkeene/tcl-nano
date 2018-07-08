#! /usr/bin/env tclsh

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

# Constants
set ::nano::block::stateBlockPreamble [binary decode hex "0000000000000000000000000000000000000000000000000000000000000006"]
set ::nano::address::base32alphabet {13456789abcdefghijkmnopqrstuwxyz}

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
			append blockData $::nano::block::stateBlockPreamble
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
	tailcall ::json::json2dict $blockJSON
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
		}

		return -level 0 [list $field [json::write string $block($field)]]
	}]
	set blockJSONEntries [join $blockJSONEntries]

	set blockJSON [json::write object {*}$blockJSONEntries]

	return $blockJSON
}

proc ::nano::block::dict::fromBlock {blockData args} {
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
			binary scan $blockData a32a32H64a32H32H64 \
				block(header) \
				block(account) \
				block(previous) \
				block(representative) \
				block(balance) \
				block(link)

			if {$block(header) ne $::nano::block::stateBlockPreamble} {
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

proc ::nano::block::json::fromBlock {blockData args} {
	set blockDict [::nano::block::dict::fromBlock $blockData {*}$args]

	set blockJSON [::nano::block::json::fromDict $blockDict]

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

proc ::nano::block::sign {blockData args} {
	set blockHash [::nano::block::hash $blockData]

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

proc ::nano::block::verifyBlock {blockData args} {
	set blockHash [::nano::block::hash $blockData]

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

	set blockHash [::nano::block::hash $blockData -binary]

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

	tailcall ::nano::block::dict::validate $blockDict
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
		set block(previous) "0000000000000000000000000000000000000000000000000000000000000000"
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

	set block(link) "0000000000000000000000000000000000000000000000000000000000000000"

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
proc ::nano::work::fromWorkData {blockHashOrPublicKey} {
	if {[string length $blockHashOrPublicKey] != $::nano::block::hashLength} {
		set blockHashOrPublicKey [binary decode hex $blockHashOrPublicKey]
	}

	set work [binary encode hex [::nano::internal::generateWork $blockHashOrPublicKey]]
	set work [string tolower $work]

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

proc ::nano::account::receive {account blockHash signKey} {
	set accountPubKey [::nano::address::toPublicKey $account -hex]

	set frontierInfo [getFrontier $account]
	dict with frontierInfo {}

	set blockInfo [dict get $::nano::account::pending $accountPubKey $blockHash]

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
	dict unset ::nano::account::pending $accountPubKey $blockHash

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

	if {![dict exists $::nano::account::pending $accountPubKey]} {
		return $outBlocks
	}

	set signKey [binary encode hex $key]
	set account [::nano::address::fromPublicKey $accountPubKey]

	foreach blockHash [dict keys [dict get $::nano::account::pending $accountPubKey]] {
		lappend outBlocks [receive $account $blockHash $signKey]
	}

	return $outBlocks
}

proc ::nano::network::_read {fd bytes} {
	if {[chan configure $fd -blocking]} {
		tailcall ::read $fd $bytes
	}

	set data ""
	while {$bytes > 0} {
		set readData [read $fd $bytes]
		if {[string length $readData] == 0} {
			if {[eof $fd]} {
				break
			} else {
				update

				continue
			}
		}

		incr bytes -[string length $readData]
		append data $readData
	}

	return $data
}
