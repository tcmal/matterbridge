package bdiscord

import (
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/starshine-sys/pkgo/v2"
)

const userAgent = "Matterbridge PluralKit Integration"

type SystemInfo struct {
	pkgo.System
	proxyRegex *regexp.Regexp
}

// PKguildcache holds cached information about pluralkit systems & members in a given guild
type PKguildcache struct {
	session *pkgo.Session
	systems map[string]*SystemInfo

	log   *logrus.Entry
	mutex *sync.RWMutex
}

func NewPkGuildCache(log *logrus.Entry, token string) *PKguildcache {
	session := pkgo.New(token)
	session.UserAgent = userAgent
	return &PKguildcache{
		session: session,
		systems: make(map[string]*SystemInfo),
		log:     log,
		mutex:   &sync.RWMutex{},
	}
}

func (gc *PKguildcache) MessageWillBeProxied(memberID string, message string) bool {
	if !gc.usesPk(memberID) {
		gc.log.Debug("User does not use pluralkit")
		return false
	}

	regex := gc.proxyMessageRegex(memberID)
	gc.log.Debug("User's proxy message regex is: ", regex)
	return regex.MatchString(message)
}

func (gc *PKguildcache) InvalidateCache(d string) {
	gc.mutex.Lock()
	defer gc.mutex.Unlock()
	delete(gc.systems, d)
}

func (gc *PKguildcache) getSystemInfo(memberID string) *SystemInfo {
	// hopefully just use value from the cache
	gc.mutex.RLock()
	val, ok := gc.systems[memberID]
	if ok {
		gc.mutex.RUnlock()
		return val
	}

	// we will want to update the cache, so upgrade to a write lock
	gc.mutex.RUnlock()
	gc.mutex.Lock()
	defer gc.mutex.Unlock()

	system, err := gc.session.System(memberID)
	if err != nil {
		// Check if it's the user not having a system, or having it private.
		// If so, cache the failure
		pkerr, ok := err.(*pkgo.PKAPIError)
		if ok && (pkerr.StatusCode == 404 || pkerr.StatusCode == 403) {
			gc.log.Debugf("Error fetching system info for %s, but it's probably not worth retrying: %s\n", memberID, err)
			gc.systems[memberID] = nil
			return nil
		}

		gc.log.Errorf("Error fetching system info for %s: %s\n", memberID, err)
		return nil
	}

	members, err := gc.session.Members(system.ID)
	if err != nil {
		pkerr, ok := err.(*pkgo.PKAPIError)
		if ok && (pkerr.StatusCode == 404 || pkerr.StatusCode == 403) {
			gc.log.Debugf("Error fetching member info for %s, but it's probably not worth retrying: %s\n", memberID, err)
			gc.systems[memberID] = nil
			return nil
		}

		gc.log.Errorf("Error fetching member info for %s: %s\n", memberID, err)
		return nil
	}

	proxyRegex, err := compileProxyRegex(members)
	if err != nil || proxyRegex == nil {
		gc.log.Errorf("Error compiling proxying regex for %s: %s\n", memberID, err)
		gc.systems[memberID] = nil
		return nil
	}

	gc.log.Debugf("Proxy regex for %s is %s", memberID, proxyRegex)

	gc.systems[memberID] = &SystemInfo{
		system,
		proxyRegex,
	}
	return gc.systems[memberID]
}

func (gc *PKguildcache) usesPk(memberID string) bool {
	return gc.getSystemInfo(memberID) != nil
}

func (gc *PKguildcache) proxyMessageRegex(memberID string) *regexp.Regexp {
	sysinfo := gc.getSystemInfo(memberID)
	if sysinfo == nil {
		return regexp.MustCompile("$^") // can never match anything
	}

	return sysinfo.proxyRegex
}

func compileProxyRegex(members []pkgo.Member) (*regexp.Regexp, error) {
	var (
		prefixPart strings.Builder
		suffixPart strings.Builder
	)
	for _, member := range members {
		for _, tag := range member.ProxyTags {
			if tag.Prefix != "" {
				if prefixPart.Len() != 0 {
					prefixPart.WriteRune('|')
				}
				prefixPart.WriteString(regexp.QuoteMeta(tag.Prefix))
			}
			if tag.Suffix != "" {
				if suffixPart.Len() != 0 {
					suffixPart.WriteRune('|')
				}
				suffixPart.WriteString(regexp.QuoteMeta(tag.Suffix))
			}
		}
	}

	var regex strings.Builder
	regex.WriteString("^(")
	regex.WriteString(prefixPart.String())
	regex.WriteString(")(.*)(")
	regex.WriteString(suffixPart.String())
	regex.WriteString(")$")

	return regexp.Compile(regex.String())
}
