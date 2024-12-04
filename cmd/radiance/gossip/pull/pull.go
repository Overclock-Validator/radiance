package pull

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"time"

	"github.com/Overclock-Validator/mithril/pkg/gossip"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "pull",
	Short: "Pull CRDS from a node",
	Args:  cobra.NoArgs,
}

var flags = Cmd.Flags()

var (
	flagAddr = flags.String("addr", "", "Address to ping (<host>:<port>)")
)

var target netip.AddrPort

func init() {
	Cmd.Run = run
}

func run(c *cobra.Command, _ []string) {
	if *flagAddr == "" {
		klog.Exit("No address specified")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *flagAddr)
	if err != nil {
		klog.Exitf("invalid target address: %s", err)
	}
	target = udpAddr.AddrPort()

	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		klog.Exit(err)
	}

	pingClient := gossip.NewPingClient(identity, conn)
	pingServer := gossip.NewPingServer(identity, conn)
	pullClient := gossip.NewPullClient(identity, conn)
	handler := &gossip.Handler{
		PingClient: pingClient,
		PingServer: pingServer,
		PullClient: pullClient,
	}
	client := gossip.NewDriver(handler, conn)

	ctx, cancel := context.WithCancel(c.Context())
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return client.Run(ctx)
	})
	group.Go(func() error {
		_, _, err := pingClient.Ping(ctx, target)
		if err != nil {
			klog.Exitf("ping ignored: %s", err)
		}
		klog.Info("Pinged")
		err = pullClient.Pull(target)
		if err != nil {
			klog.Exitf("failed to send pull request: %s", err)
		}
		err = pullClient.Pull(target)
		if err != nil {
			klog.Exitf("failed to send pull request: %s", err)
		}

		time.Sleep(2 * time.Second)

		err = pullClient.Pull(target)
		if err != nil {
			klog.Exitf("failed to send pull request: %s", err)
		}

		time.Sleep(3 * time.Second)
		return context.Canceled // done
	})
	_ = group.Wait()
	_ = conn.Close()
}
