package ifneeded nano 0 [list apply {{dir} {
	load [file join $dir nano.so]
	source [file join $dir nano.tcl]
}} $dir]
