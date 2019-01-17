#! /usr/bin/env tclsh

package require starkit
starkit::startup

apply {{} {
	set topdir $::starkit::topdir

	switch -glob -- [info nameofexecutable] {
		"*-rpc-client" - "rpc-client" - "rpc-client.*" {
			set mode "rpc-client"
		}
		default {
			set mode "node"

			# XXX: Override the built-in log file location
			set ::logfd [open node.log a+]
		}
	}

	package require nano
	set nanoVersion [package present nano]

	set nanoDir [file join $topdir lib tcl-nano${nanoVersion}]

	tailcall source [file join $nanoDir bin $mode]
}}
