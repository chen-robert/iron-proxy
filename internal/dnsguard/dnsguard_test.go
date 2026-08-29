// Modified by crypto-scan from upstream IronProxy v0.49.0.
package dnsguard

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNew_RejectsBareIPs(t *testing.T) {
	tests := []string{
		"1.2.3.4",
		"169.254.169.254",
		"::1",
		"fd00:ec2::254",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := New([]string{in})
			require.Error(t, err)
			require.Contains(t, err.Error(), "must be CIDR notation")
		})
	}
}

func TestNew_RejectsMalformed(t *testing.T) {
	tests := []string{
		"not-an-ip/24",
		"999.999.999.999/32",
		"10.0.0.0/99",
		"  ",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := New([]string{in})
			require.Error(t, err)
		})
	}
}

func TestNew_AcceptsValid(t *testing.T) {
	g, err := New([]string{
		"169.254.169.254/32",
		"127.0.0.0/8",
		"::1/128",
		"fd00:ec2::254/128",
		"10.0.0.0/8",
	})
	require.NoError(t, err)
	require.NotNil(t, g)
}

func TestNew_NilAndEmpty(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.False(t, g.IsDenied(netip.MustParseAddr("169.254.169.254")))

	g, err = New([]string{})
	require.NoError(t, err)
	require.False(t, g.IsDenied(netip.MustParseAddr("127.0.0.1")))
}

func TestIsDenied(t *testing.T) {
	g, err := New([]string{
		"169.254.169.254/32",
		"127.0.0.0/8",
		"::1/128",
	})
	require.NoError(t, err)

	denied := []string{
		"169.254.169.254",
		"127.0.0.1",
		"127.255.255.254",
		"::1",
	}
	for _, ip := range denied {
		t.Run("denied/"+ip, func(t *testing.T) {
			require.True(t, g.IsDenied(netip.MustParseAddr(ip)))
		})
	}

	allowed := []string{
		"169.254.169.253",
		"169.254.170.0",
		"128.0.0.0",
		"8.8.8.8",
		"::2",
		"2001:db8::1",
	}
	for _, ip := range allowed {
		t.Run("allowed/"+ip, func(t *testing.T) {
			require.False(t, g.IsDenied(netip.MustParseAddr(ip)))
		})
	}
}

func TestIsDenied_4in6Mapped(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8"})
	require.NoError(t, err)

	mapped := netip.MustParseAddr("::ffff:127.0.0.1")
	require.True(t, g.IsDenied(mapped))
}

func TestDialControl_DenyAndAllow(t *testing.T) {
	g, err := New([]string{
		"127.0.0.0/8",
		"169.254.169.254/32",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"::/3",
		"2001:db8::/32",
	})
	require.NoError(t, err)

	t.Run("denied ipv4", func(t *testing.T) {
		err := g.DialControl("tcp", "127.0.0.1:443", nil)
		require.Error(t, err)
		require.True(t, IsDenyError(err))
	})

	t.Run("denied imds", func(t *testing.T) {
		err := g.DialControl("tcp", "169.254.169.254:80", nil)
		require.Error(t, err)
		var de *DenyError
		require.ErrorAs(t, err, &de)
		require.Equal(t, "169.254.169.254", de.Address)
	})

	for _, address := range []string{
		"198.18.0.1:443",
		"198.51.100.8:443",
		"[100::1]:443",
		"[2001:db8::1]:443",
	} {
		t.Run("denied special use "+address, func(t *testing.T) {
			err := g.DialControl("tcp", address, nil)
			require.Error(t, err)
			require.True(t, IsDenyError(err))
		})
	}

	t.Run("allowed ipv4", func(t *testing.T) {
		require.NoError(t, g.DialControl("tcp", "8.8.8.8:443", nil))
	})

	t.Run("4-in-6 mapped denied", func(t *testing.T) {
		err := g.DialControl("tcp", "[::ffff:127.0.0.1]:443", nil)
		require.Error(t, err)
		require.True(t, IsDenyError(err))
	})

	t.Run("malformed address allowed", func(t *testing.T) {
		// Not our job to reject malformed addresses — Go's connect will fail.
		require.NoError(t, g.DialControl("tcp", "not-an-address", nil))
	})
}

func TestDialControl_EmptyGuardNoop(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}

func TestDialContextRejectsDeniedAddressAfterHostnameResolution(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8", "::1/128"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	connection, err := g.DialContext(
		ctx,
		&net.Dialer{Timeout: time.Second},
		"tcp",
		"localhost:443",
	)
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err)
	require.True(t, IsDenyError(err), "resolved loopback must fail at the dial guard")
}

func TestDialControl_NilGuardNoop(t *testing.T) {
	var g *Guard
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}

func TestPrivateException_IsExactHostnameAndAddress(t *testing.T) {
	g, err := NewWithExceptions(
		[]string{"10.0.0.0/8", "169.254.0.0/16"},
		map[string][]string{"managed-rpc": {"10.23.4.5/32"}},
	)
	require.NoError(t, err)

	require.NoError(t, g.dialControlForHost("managed-rpc", "10.23.4.5:8899"))
	require.NoError(t, g.dialControlForHost("MANAGED-RPC.", "10.23.4.5:8899"))
	require.Error(t, g.dialControlForHost("managed-rpc", "10.23.4.6:8899"))
	require.Error(t, g.dialControlForHost("other-rpc", "10.23.4.5:8899"))
	require.Error(t, g.dialControlForHost("10.23.4.5", "10.23.4.5:8899"))
	require.Error(t, g.dialControlForHost("managed-rpc", "169.254.169.254:80"))
	// The compatibility hook has no original hostname and therefore never
	// applies private exceptions.
	require.Error(t, g.DialControl("tcp", "10.23.4.5:8899", nil))
}

func TestPrivateException_RejectsUnsafeConfiguration(t *testing.T) {
	for _, host := range []string{"", "*", "*.example", "10.0.0.1", "rpc:8899", "-rpc"} {
		t.Run(host, func(t *testing.T) {
			_, err := NewWithExceptions(
				[]string{"10.0.0.0/8"},
				map[string][]string{host: {"10.0.0.2/32"}},
			)
			require.Error(t, err)
		})
	}
	_, err := NewWithExceptions(
		[]string{"10.0.0.0/8"},
		map[string][]string{"managed-rpc": {"10.0.0.2"}},
	)
	require.Error(t, err)
	for _, prefix := range []string{"10.0.0.0/8", "2001:db8::/64"} {
		_, err = NewWithExceptions(
			[]string{"10.0.0.0/8", "2001:db8::/32"},
			map[string][]string{"managed-rpc": {prefix}},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exactly one address")
	}
}
