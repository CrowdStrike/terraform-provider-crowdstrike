// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// This file is derived from github.com/hashicorp/terraform-plugin-framework-timetypes.

package types_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
)

func TestRFC3339_StringSemanticEquals(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		currentRFC3339time fwtypes.RFC3339
		givenRFC3339time   basetypes.StringValuable
		expectedMatch      bool
		expectedDiags      diag.Diagnostics
	}{
		"not equal - different dates": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-26T23:43:16Z"),
			expectedMatch:      false,
		},
		"not equal - different times": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T23:01:16Z"),
			expectedMatch:      false,
		},
		"not equal - different offset times": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16+03:00"),
			expectedMatch:      false,
		},
		"semantically equal - UTC time and local time resolving to same instant": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16-03:00"),
			expectedMatch:      true,
		},
		"semantically equal - Z suffix and positive zero num offset": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16+00:00"),
			expectedMatch:      true,
		},
		"semantically equal - Z suffix and negative zero num offset": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16-00:00"),
			expectedMatch:      true,
		},
		"semantically equal - negative zero and positive zero num offset": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16-00:00"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16+00:00"),
			expectedMatch:      true,
		},
		"semantically equal - byte for byte match": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			expectedMatch:      true,
		},
		"semantically equal - positive offset and UTC resolving to same instant": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2026-07-01T00:00:00+10:00"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2026-06-30T14:00:00Z"),
			expectedMatch:      true,
		},
		"semantically equal - negative offset and UTC resolving to same instant": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2026-01-15T12:00:00-05:00"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2026-01-15T17:00:00Z"),
			expectedMatch:      true,
		},
		"not equal - same wall clock, different offsets": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2026-07-01T00:00:00+10:00"),
			givenRFC3339time:   fwtypes.NewRFC3339ValueMust("2026-07-01T00:00:00Z"),
			expectedMatch:      false,
		},
		"error - not given RFC3339 value": {
			currentRFC3339time: fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			givenRFC3339time:   basetypes.NewStringValue("0000-00-00T00:00:00-00:00"),
			expectedMatch:      false,
			expectedDiags: diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"Semantic Equality Check Error",
					"An unexpected value type was received while performing semantic equality checks. "+
						"Please report this to the provider developers.\n\n"+
						"Expected Value Type: types.RFC3339\n"+
						"Got Value Type: basetypes.StringValue",
				),
			},
		},
	}
	for name, testCase := range testCases {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			match, diags := testCase.currentRFC3339time.StringSemanticEquals(context.Background(), testCase.givenRFC3339time)

			if testCase.expectedMatch != match {
				t.Errorf("Expected StringSemanticEquals to return: %t, but got: %t", testCase.expectedMatch, match)
			}

			if diff := cmp.Diff(diags, testCase.expectedDiags); diff != "" {
				t.Errorf("Unexpected diagnostics (-got, +expected): %s", diff)
			}
		})
	}
}

func TestRFC3339ValidateAttribute(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		RFC3339       fwtypes.RFC3339
		expectedDiags diag.Diagnostics
	}{
		"empty-struct": {
			RFC3339: fwtypes.RFC3339{},
		},
		"null": {
			RFC3339: fwtypes.NewRFC3339Null(),
		},
		"unknown": {
			RFC3339: fwtypes.NewRFC3339Unknown(),
		},
		"valid RFC3339": {
			RFC3339: fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16+00:00"),
		},
		"valid RFC3339 - Zulu": {
			RFC3339: fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16Z"),
		},
		"valid RFC3339 - UTC Offset": {
			RFC3339: fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16-05:00"),
		},
		"invalid RFC3339 - no date": {
			RFC3339: fwtypes.RFC3339{
				StringValue: basetypes.NewStringValue("20:43:16-05:00"),
			},
			expectedDiags: diag.Diagnostics{
				diag.NewAttributeErrorDiagnostic(
					path.Root("test"),
					"Invalid RFC3339 String Value",
					"A string value was provided that is not valid RFC3339 string format.\n\n"+
						"Given Value: 20:43:16-05:00\n"+
						"Error: parsing time \"20:43:16-05:00\" as \"2006-01-02T15:04:05Z07:00\": "+
						"cannot parse \"20:43:16-05:00\" as \"2006\"",
				),
			},
		},
		"invalid RFC3339 - no time": {
			RFC3339: fwtypes.RFC3339{
				StringValue: basetypes.NewStringValue("2023-07-25T"),
			},
			expectedDiags: diag.Diagnostics{
				diag.NewAttributeErrorDiagnostic(
					path.Root("test"),
					"Invalid RFC3339 String Value",
					"A string value was provided that is not valid RFC3339 string format.\n\n"+
						"Given Value: 2023-07-25T\n"+
						"Error: parsing time \"2023-07-25T\" as \"2006-01-02T15:04:05Z07:00\": "+
						"cannot parse \"\" as \"15\"",
				),
			},
		},
		"invalid RFC3339 - normal string": {
			RFC3339: fwtypes.RFC3339{
				StringValue: basetypes.NewStringValue("notvalidrfc3339"),
			},
			expectedDiags: diag.Diagnostics{
				diag.NewAttributeErrorDiagnostic(
					path.Root("test"),
					"Invalid RFC3339 String Value",
					"A string value was provided that is not valid RFC3339 string format.\n\n"+
						"Given Value: notvalidrfc3339\n"+
						"Error: parsing time \"notvalidrfc3339\" as \"2006-01-02T15:04:05Z07:00\": "+
						"cannot parse \"notvalidrfc3339\" as \"2006\"",
				),
			},
		},
	}
	for name, testCase := range testCases {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := xattr.ValidateAttributeResponse{}

			testCase.RFC3339.ValidateAttribute(
				context.Background(),
				xattr.ValidateAttributeRequest{
					Path: path.Root("test"),
				},
				&resp,
			)

			if diff := cmp.Diff(resp.Diagnostics, testCase.expectedDiags); diff != "" {
				t.Errorf("Unexpected diagnostics (-got, +expected): %s", diff)
			}
		})
	}
}

func TestRFC3339ValidateParameter(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		RFC3339         fwtypes.RFC3339
		expectedFuncErr *function.FuncError
	}{
		"empty-struct": {
			RFC3339: fwtypes.RFC3339{},
		},
		"null": {
			RFC3339: fwtypes.NewRFC3339Null(),
		},
		"unknown": {
			RFC3339: fwtypes.NewRFC3339Unknown(),
		},
		"valid RFC3339": {
			RFC3339: fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16+00:00"),
		},
		"valid RFC3339 - Zulu": {
			RFC3339: fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16Z"),
		},
		"valid RFC3339 - UTC Offset": {
			RFC3339: fwtypes.NewRFC3339ValueMust("2023-07-25T20:43:16-05:00"),
		},
		"invalid RFC3339 - no date": {
			RFC3339: fwtypes.RFC3339{
				StringValue: basetypes.NewStringValue("20:43:16-05:00"),
			},
			expectedFuncErr: function.NewArgumentFuncError(
				0,
				"Invalid RFC3339 String Value: "+
					"A string value was provided that is not valid RFC3339 string format.\n\n"+
					"Given Value: 20:43:16-05:00\n"+
					"Error: parsing time \"20:43:16-05:00\" as \"2006-01-02T15:04:05Z07:00\": "+
					"cannot parse \"20:43:16-05:00\" as \"2006\"",
			),
		},
		"invalid RFC3339 - no time": {
			RFC3339: fwtypes.RFC3339{
				StringValue: basetypes.NewStringValue("2023-07-25T"),
			},
			expectedFuncErr: function.NewArgumentFuncError(
				0,
				"Invalid RFC3339 String Value: "+
					"A string value was provided that is not valid RFC3339 string format.\n\n"+
					"Given Value: 2023-07-25T\n"+
					"Error: parsing time \"2023-07-25T\" as \"2006-01-02T15:04:05Z07:00\": "+
					"cannot parse \"\" as \"15\"",
			),
		},
		"invalid RFC3339 - normal string": {
			RFC3339: fwtypes.RFC3339{
				StringValue: basetypes.NewStringValue("notvalidrfc3339"),
			},
			expectedFuncErr: function.NewArgumentFuncError(
				0,
				"Invalid RFC3339 String Value: "+
					"A string value was provided that is not valid RFC3339 string format.\n\n"+
					"Given Value: notvalidrfc3339\n"+
					"Error: parsing time \"notvalidrfc3339\" as \"2006-01-02T15:04:05Z07:00\": "+
					"cannot parse \"notvalidrfc3339\" as \"2006\"",
			),
		},
	}
	for name, testCase := range testCases {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := function.ValidateParameterResponse{}

			testCase.RFC3339.ValidateParameter(
				context.Background(),
				function.ValidateParameterRequest{
					Position: int64(0),
				},
				&resp,
			)

			if diff := cmp.Diff(resp.Error, testCase.expectedFuncErr); diff != "" {
				t.Errorf("Unexpected diagnostics (-got, +expected): %s", diff)
			}
		})
	}
}

func TestRFC3339_ValueRFC3339Time(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		RFC3339           fwtypes.RFC3339
		expectedTimestamp string
		expectedDiags     diag.Diagnostics
	}{
		"RFC3339 string value is null ": {
			RFC3339: fwtypes.NewRFC3339Null(),
			expectedDiags: diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"RFC3339 ValueRFC3339Time Error",
					"RFC3339 string value is null",
				),
			},
		},
		"RFC3339 string value is unknown ": {
			RFC3339: fwtypes.NewRFC3339Unknown(),
			expectedDiags: diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"RFC3339 ValueRFC3339Time Error",
					"RFC3339 string value is unknown",
				),
			},
		},
		"valid RFC3339 Timestamp - Zulu suffix": {
			RFC3339:           fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16Z"),
			expectedTimestamp: "2023-07-25T23:43:16Z",
		},
		"valid RFC3339 Timestamp - UTC offset ": {
			RFC3339:           fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16-00:00"),
			expectedTimestamp: "2023-07-25T23:43:16-00:00",
		},
		"valid RFC3339 Timestamp - EDT offset ": {
			RFC3339:           fwtypes.NewRFC3339ValueMust("2023-07-25T23:43:16-04:00"),
			expectedTimestamp: "2023-07-25T23:43:16-04:00",
		},
	}
	for name, testCase := range testCases {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rfc3339Time, diags := testCase.RFC3339.ValueRFC3339Time()
			expectedRFC3339Time, _ := time.Parse(time.RFC3339, testCase.expectedTimestamp)

			if rfc3339Time != expectedRFC3339Time {
				t.Errorf("Unexpected difference in time.Time, got: %s, expected: %s", rfc3339Time, expectedRFC3339Time)
			}

			if diff := cmp.Diff(diags, testCase.expectedDiags); diff != "" {
				t.Errorf("Unexpected diagnostics (-got, +expected): %s", diff)
			}
		})
	}
}
