#! /usr/bin/env tclsh

lappend auto_path [pwd]
lappend auto_path /opt/appfs/rkeene.org/tcllib/platform/latest/lib
lappend auto_path /opt/appfs/rkeene.org/tclreadline/platform/latest/lib
lappend auto_path [file join [pwd] lib]

package require nano

## Set defaults
set url {http://[::1]:55000/}

## Process
if {[llength $argv] % 2 != 0} {
	lappend argv ""
}
foreach {opt optval} $argv {
	switch -- $opt {
		"--url" {
			set url $optval
		}
		"-h" - "--help" {
			puts "Usage: rpc-client \[--help\] \[--url <rpc-url>\]"
			exit 0
		}
		default {
			puts stderr "Invalid option: $opt"
			exit 1
		}
	}
}

# Override logging, to file
proc ::nano::node::user_log {line} {
	if {![info exists ::logfd]} {
		set ::logfd [open "node.log" a+]
		fconfigure $::logfd -blocking false
	}

	puts $::logfd $line
	flush $::logfd
}


nano::rpc::client::init -url $url
::nano::rpc::cli -interactive
