package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnelParser_ParseL2TPRemoteAccess(t *testing.T) {
	config := `ip lan1 address 192.168.0.1/24
tunnel select 1
 tunnel encapsulation l2tp
 ipsec tunnel 101
  ipsec sa policy 101 1 esp aes-cbc sha256-hmac
 l2tp tunnel disconnect time off
 l2tp keepalive use on 10 3
 l2tp keepalive log on
 ip tunnel tcp mss limit auto
tunnel enable 1
ipsec auto refresh on
ipsec ike encryption 1 aes-cbc
ipsec ike group 1 modp2048
ipsec ike hash 1 sha256
ipsec ike keepalive use 1 off
ipsec ike local address 1 192.168.1.3
ipsec ike nat-traversal 1 on
ipsec ike pre-shared-key 1 text secret123
ipsec ike remote address 1 any
pp select anonymous
 pp bind tunnel1
 pp auth request mschap-v2
 pp auth username vpnuser vpnpass
 ppp ipcp ipaddress on
 ppp ipcp msext on
 ppp ccp type none
 ip pp remote address pool 192.168.0.220-192.168.0.229
 ip pp mtu 1258
pp enable anonymous
l2tp service on
`

	parser := NewTunnelParser()
	tunnels, err := parser.ParseTunnelConfig(config)

	require.NoError(t, err)
	require.Len(t, tunnels, 1)

	tunnel := tunnels[0]
	assert.Equal(t, 1, tunnel.ID)
	assert.Equal(t, "l2tp", tunnel.Encapsulation)
	assert.True(t, tunnel.Enabled)

	require.NotNil(t, tunnel.IPsec)
	assert.Equal(t, 101, tunnel.IPsec.IPsecTunnelID)
	assert.Equal(t, "192.168.1.3", tunnel.IPsec.LocalAddress)
	assert.Equal(t, "any", tunnel.IPsec.RemoteAddress)
	assert.Equal(t, "secret123", tunnel.IPsec.PreSharedKey)
	assert.True(t, tunnel.IPsec.NATTraversal)
	assert.True(t, tunnel.IPsec.AutoRefresh)

	assert.True(t, tunnel.IPsec.IKEv2Proposal.EncryptionAES128)
	assert.True(t, tunnel.IPsec.IKEv2Proposal.IntegritySHA256)
	assert.False(t, tunnel.IPsec.IKEv2Proposal.IntegritySHA1)
	assert.True(t, tunnel.IPsec.IKEv2Proposal.GroupFourteen)

	require.NotNil(t, tunnel.IPsec.Keepalive)
	assert.False(t, tunnel.IPsec.Keepalive.Enabled)
	assert.Equal(t, "off", tunnel.IPsec.Keepalive.Mode)

	assert.True(t, tunnel.IPsec.Transform.EncryptionAES128)
	assert.True(t, tunnel.IPsec.Transform.IntegritySHA256)
	assert.Equal(t, "auto", tunnel.IPsec.TCPMSSLimit)

	require.NotNil(t, tunnel.L2TP)
	assert.Equal(t, 0, tunnel.L2TP.DisconnectTime)
	require.NotNil(t, tunnel.L2TP.Keepalive)
	assert.True(t, tunnel.L2TP.Keepalive.Enabled)
	assert.Equal(t, 10, tunnel.L2TP.Keepalive.Interval)
	assert.Equal(t, 3, tunnel.L2TP.Keepalive.Retry)
	assert.True(t, tunnel.L2TP.KeepaliveLog)

	require.NotNil(t, tunnel.L2TP.Authentication)
	assert.Equal(t, "mschap-v2", tunnel.L2TP.Authentication.RequestMethod)
	require.Len(t, tunnel.L2TP.Authentication.Users, 1)
	assert.Equal(t, "vpnuser", tunnel.L2TP.Authentication.Users[0].Name)
	assert.Equal(t, "vpnpass", tunnel.L2TP.Authentication.Users[0].Password)

	require.NotNil(t, tunnel.L2TP.IPPool)
	assert.Equal(t, "192.168.0.220", tunnel.L2TP.IPPool.Start)
	assert.Equal(t, "192.168.0.229", tunnel.L2TP.IPPool.End)

	assert.True(t, tunnel.L2TP.IPCPIPAddress)
	assert.True(t, tunnel.L2TP.IPCPMSExt)
	assert.True(t, tunnel.L2TP.CCPTypeNone)
	assert.Equal(t, 1258, tunnel.L2TP.MTU)
}

func TestBuildTunnelCommands_L2TPRemoteAccess(t *testing.T) {
	tunnel := Tunnel{
		ID:            1,
		Encapsulation: "l2tp",
		Enabled:       true,
		IPsec: &TunnelIPsec{
			IPsecTunnelID: 101,
			LocalAddress:  "192.168.1.3",
			RemoteAddress: "any",
			PreSharedKey:  "secret123",
			NATTraversal:  true,
			AutoRefresh:   true,
			IKEv2Proposal: IKEv2Proposal{
				EncryptionAES128: true,
				IntegritySHA256:  true,
				GroupFourteen:    true,
			},
			Transform: IPsecTransform{
				Protocol:         "esp",
				EncryptionAES128: true,
				IntegritySHA256:  true,
			},
			Keepalive: &TunnelIPsecKeepalive{
				Enabled: false,
				Mode:    "off",
			},
			TCPMSSLimit: "auto",
		},
		L2TP: &TunnelL2TP{
			DisconnectTime: 0,
			KeepaliveLog:   true,
			Keepalive: &TunnelL2TPKeepalive{
				Enabled:  true,
				Interval: 10,
				Retry:    3,
			},
			Authentication: &L2TPAuth{
				RequestMethod: "mschap-v2",
				Users: []L2TPUser{
					{Name: "vpnuser", Password: "vpnpass"},
				},
			},
			IPPool: &L2TPIPPool{
				Start: "192.168.0.220",
				End:   "192.168.0.229",
			},
			IPCPIPAddress: true,
			IPCPMSExt:     true,
			CCPTypeNone:   true,
			MTU:           1258,
		},
	}

	commands := BuildTunnelCommands(tunnel)

	expected := []string{
		"tunnel select 1",
		"tunnel encapsulation l2tp",
		"ipsec tunnel 101",
		"ipsec sa policy 101 1 esp aes-cbc sha256-hmac",
		"ipsec ike local address 1 192.168.1.3",
		"ipsec ike remote address 1 any",
		"ipsec ike pre-shared-key 1 text secret123",
		"ipsec ike encryption 1 aes-cbc",
		"ipsec ike hash 1 sha256",
		"ipsec ike group 1 modp2048",
		"ipsec ike nat-traversal 1 on",
		"ipsec ike keepalive use 1 off",
		"no ip tunnel secure filter in",
		"no ip tunnel secure filter out",
		"ip tunnel tcp mss limit auto",
		"l2tp tunnel disconnect time off",
		"l2tp keepalive use on 10 3",
		"l2tp keepalive log on",
		"tunnel enable 1",
		"ipsec auto refresh on",
		"pp select anonymous",
		"pp bind tunnel1",
		"pp auth request mschap-v2",
		"pp auth username vpnuser vpnpass",
		"ppp ipcp ipaddress on",
		"ppp ipcp msext on",
		"ppp ccp type none",
		"ip pp remote address pool 192.168.0.220-192.168.0.229",
		"ip pp mtu 1258",
		"pp enable anonymous",
		"pp select none",
	}

	assert.Equal(t, expected, commands)
}

func TestBuildTunnelCommands_KeepaliveOffOnly(t *testing.T) {
	tunnel := Tunnel{
		ID:            2,
		Encapsulation: "ipsec",
		Enabled:       true,
		IPsec: &TunnelIPsec{
			IPsecTunnelID: 2,
			PreSharedKey:  "secret",
			Keepalive: &TunnelIPsecKeepalive{
				Enabled: false,
				Mode:    "off",
			},
		},
	}

	commands := BuildTunnelCommands(tunnel)
	assert.Contains(t, commands, "ipsec ike keepalive use 2 off")
	assert.NotContains(t, commands, "ipsec auto refresh on")
	assert.NotContains(t, commands, "pp select anonymous")
}

func TestBuildTunnelCommands_KeepaliveDisabledWithoutOffMode(t *testing.T) {
	tunnel := Tunnel{
		ID:            3,
		Encapsulation: "ipsec",
		Enabled:       true,
		IPsec: &TunnelIPsec{
			IPsecTunnelID: 3,
			PreSharedKey:  "secret",
			Keepalive: &TunnelIPsecKeepalive{
				Enabled: false,
				Mode:    "dpd",
			},
		},
	}

	commands := BuildTunnelCommands(tunnel)
	for _, cmd := range commands {
		assert.NotContains(t, cmd, "keepalive use")
	}
}
