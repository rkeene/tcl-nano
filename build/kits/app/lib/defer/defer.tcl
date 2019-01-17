namespace eval ::defer {
	namespace export defer

	variable idVar "<defer>\n<trace variable>"
}

proc ::defer::with {args} {
	if {[llength $args] == 1} {
		set varlist [list]
		set code [lindex $args 0]
	} elseif {[llength $args] == 2} {
		set varlist [lindex $args 0]
		set code [lindex $args 1]
	} else {
		return -code error "wrong # args: defer::with ?varlist? script"
	}

	if {[info level] == 1} {
		set global true
	} else {
		set global false
	}

	# We can't reliably handle cleanup from the global scope, don't let people
	# register ineffective handlers for now
	if {$global} {
		return -code error "defer may not be used from the global scope"
	}

	# Generate an ID to un-defer if requested
	set id [clock clicks]
	for {set i 0} {$i < 5} {incr i} {
		append id [expr rand()]
	}

	# If a list of variable names has been supplied, slurp up their values
	# and add the appropriate script to set those variables in the lambda
	## Generate a list of commands to create the variables
	foreach var $varlist {
		if {![uplevel 1 [list info exists $var]]} {
			continue
		}

		if {[uplevel 1 [list array exists $var]]} {
			set val [uplevel 1 [list array get $var]]
			lappend codeSetVars [list unset -nocomplain $var]
			lappend codeSetVars [list array set $var $val]
		} else {
			set val [uplevel 1 [list set $var]]
			lappend codeSetVars [list set $var $val]
		}
	}

	## Format the above commands in the structure of a Tcl command
	if {[info exists codeSetVars]} {
		set codeSetVars [join $codeSetVars "; "]
		set code "${codeSetVars}; ${code}"
	}

	## Unset the "args" variable, which is just an artifact of the lambda
	set code "# ${id}\nunset args; ${code}"

	# Register our interest in a variable to monitor for it to disappear

	uplevel 1 [list trace add variable $::defer::idVar unset [list apply [list args $code]]]

	return $id
}

proc ::defer::defer {args} {
	set code $args
	tailcall ::defer::with $code
}

proc ::defer::autowith {script} {
	tailcall ::defer::with [uplevel 1 {info vars}] $script
}

proc ::defer::cancel {args} {
	set idList $args

	set traces [uplevel 1 [list trace info variable $::defer::idVar]]

	foreach trace $traces {
		set action [lindex $trace 0]
		set code   [lindex $trace 1]

		foreach id $idList {
			if {[string match "*# $id*" $code]} {
				uplevel 1 [list trace remove variable $::defer::idVar $action $code]
			}
		}
	}
}

package provide defer 1
