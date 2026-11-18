// Package apps contains the user-facing front ends of safe deposit box.
package apps

// Runnable is an abstraction for an application that runs with the given
// arguments and returns a process exit code.
type Runnable interface {
	Run(args []string) int
}

var _ Runnable = (*CLI)(nil)
