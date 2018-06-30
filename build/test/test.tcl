#! /usr/bin/env tclsh

lappend auto_path [file join [file dirname [info script]] .. ..]

package require nano

set key [binary decode hex 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]
puts "Key Length: [string length $key]"
set signed [binary encode hex [::nano::internal::sign "" $key]]

puts $signed
