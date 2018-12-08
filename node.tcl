#! /usr/bin/env tclsh

package require nano

# Process command-line options
## Set defaults
set network main

## Process
if {[llength $argv] % 2 != 0} {
	lappend argv ""
}
foreach {opt optval} $argv {
	switch -- $opt {
		"--network" {
			set network $optval
		}
		"-h" - "--help" {
			puts "Usage: node \[--help\] \[--network {main|beta}\]"
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
		set logfile [file join [file dirname [info script]] "node.log"]
		set ::logfd [open $logfile a+]
		fconfigure $::logfd -blocking false
	}

	puts $::logfd $line
	flush $::logfd
}

::nano::node::configure $network
::nano::node::start -bootstrap false -wait false
::nano::node::cli -interactive
