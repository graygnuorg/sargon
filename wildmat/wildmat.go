package wildmat

const (
	wildFalse = iota
	wildTrue
	wildAbort
)

const (
	GlobLex = iota
	GlobPath
	GlobStar
)

type wildMat struct {
	glob int
	pattern []rune
	patternLen int
	patternIdx int
	name []rune
	nameLen int
	nameIdx int
}

func (wm *wildMat) endOfPattern() bool {
	return wm.patternIdx == wm.patternLen
}

func (wm *wildMat) patternNext() bool {
	wm.patternIdx += 1
	return !wm.endOfPattern()
}

func (wm *wildMat) endOfName() bool {
	return wm.nameIdx == wm.nameLen
}

func (wm *wildMat) matchClass() int {
	var expect bool

	if !wm.patternNext() {
		return wildAbort
	}

	if wm.pattern[wm.patternIdx] == '^' {
		expect = false
		if !wm.patternNext() {
			return wildAbort
		}
	} else {
		expect = true
	}

	c := wm.name[wm.nameIdx]

	var rc bool
	if wm.pattern[wm.patternIdx] == '-' {
		rc = c == wm.pattern[wm.patternIdx]
		if !wm.patternNext() {
			return wildAbort
		}
	}

	if wm.pattern[wm.patternIdx] == ']' {
		if rc != expect {
			rc = c == wm.pattern[wm.patternIdx]
		}
		if !wm.patternNext() {
			return wildAbort
		}
	}

	for !wm.endOfPattern() {
		if wm.pattern[wm.patternIdx] == ']' {
			wm.patternNext()
			if rc == expect {
				return wildTrue
			} else {
				return wildFalse
			}
		}

		if rc == expect {
			wm.patternNext()
		} else if wm.patternIdx + 2 < wm.patternLen && wm.pattern[wm.patternIdx + 1] == '-' {
			rc = int(wm.pattern[wm.patternIdx]) <= int(c) && int(c) <= int(wm.pattern[wm.patternIdx+2])
			wm.patternIdx += 3
		} else {
			rc = wm.pattern[wm.patternIdx] == c
			wm.patternIdx += 1
		}

	}

	return wildAbort
}

func (wm *wildMat) Match() int {
	for !wm.endOfPattern() {
		if wm.endOfName() {
			return wildAbort
		}
		switch wm.pattern[wm.patternIdx] {
		case '*':
			var matchSlash bool
			switch wm.glob {
			case GlobLex:
				for {
					if !wm.patternNext() {
						return wildTrue
					}
					if wm.pattern[wm.patternIdx] != '*' {
						break;
					}
				}
				matchSlash = true

			case GlobPath:
				for {
					if !wm.patternNext() {
						for !wm.endOfName() {
							if wm.name[wm.nameIdx] == '/' {
								return wildFalse
							}
						}
						return wildTrue
					}
					if wm.pattern[wm.patternIdx] != '*' {
						break;
					}
				}
				matchSlash = false

			case GlobStar:
				if !wm.patternNext() {
					for !wm.endOfName() {
						if wm.name[wm.nameIdx] == '/' {
							return wildFalse
						}
					}
					return wildTrue
				} else if wm.pattern[wm.patternIdx] == '*' {
					if !wm.patternNext() {
						return wildTrue
					}
					matchSlash = true
				} else {
					matchSlash = false
				}
			}

			for !wm.endOfName() {
				if !matchSlash && wm.name[wm.nameIdx] == '/' {
					break
				}

				nwm := *wm
				if res := (&nwm).Match(); res != wildFalse {
					return res
				}
				wm.nameIdx += 1
			}
			return wildAbort

		case '?':
			if wm.glob != GlobLex && wm.name[wm.nameIdx] == '/' {
				return wildFalse
			}
			wm.patternIdx += 1
			wm.nameIdx += 1

		case '[':
			if res := wm.matchClass(); res != wildTrue {
				return res
			}
			wm.nameIdx += 1

		case '\\':
			if wm.patternIdx + 1 < wm.patternLen {
				c := wm.pattern[wm.patternIdx + 1]
				wm.patternIdx += 2
				switch c {
				case 'a':
					c = '\a'
				case 'b':
					c = '\b'
				case 'f':
					c = '\f'
				case 'n':
					c = '\n'
				case 'r':
					c = '\r'
				case 't':
					c = '\t'
				case 'v':
					c = '\v'
				}

				if wm.name[wm.nameIdx] != c {
					return wildFalse
				}

				wm.nameIdx += 1
				break
			}
			fallthrough

		default:
			if wm.pattern[wm.patternIdx] != wm.name[wm.nameIdx] {
				return wildFalse
			}
			wm.patternIdx += 1
			wm.nameIdx += 1
		}
	}
	if wm.endOfName() {
		return wildTrue
	}
	return wildFalse
}

func Match(pattern, name string, glob int) bool {
	wm := wildMat{
		glob: glob,
		pattern: []rune(pattern),
		patternLen: len(pattern),
		name: []rune(name),
		nameLen: len(name)}
	return wm.Match() == wildTrue
}
