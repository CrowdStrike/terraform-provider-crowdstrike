package modifiers

// This file previously contained string modifier implementations.
// The modifiers have been moved to separate files for better organization:
//
// - PreventStringClearing: see prevent_string_clearing.go
// - StringClearingRequiresReplace: see string_clearing_requires_replace.go
//
// All public functions are still available in the same package and can be
// imported and used exactly as before.