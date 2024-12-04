package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"github.com/Overclock-Validator/mithril/cmd/radiance/blockstore"
	"github.com/Overclock-Validator/mithril/cmd/radiance/gossip"
	"github.com/Overclock-Validator/mithril/cmd/radiance/replay"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	// Load in instruction pretty-printing
	_ "github.com/gagliardetto/solana-go/programs/system"
	_ "github.com/gagliardetto/solana-go/programs/vote"
)

var cmd = cobra.Command{
	Use:   "radiance",
	Short: "Solana Go playground",
}

func init() {
	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	klog.InitFlags(klogFlags)
	cmd.PersistentFlags().AddGoFlagSet(klogFlags)

	cmd.AddCommand(
		&blockstore.Cmd,
		&gossip.Cmd,
		&replay.Cmd,
	)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	cobra.CheckErr(cmd.ExecuteContext(ctx))
}
