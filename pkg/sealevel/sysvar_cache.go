package sealevel

type SysvarCache struct {
	recentBlockHashes *SysvarRecentBlockhashes
}

func (sysvarCache *SysvarCache) RecentBlockHashes() *SysvarRecentBlockhashes {
	return sysvarCache.recentBlockHashes
}
