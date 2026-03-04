package checks

// CheckWikiEnabled checks whether the wiki is enabled on a repository.
func CheckWikiEnabled(hasWiki bool) Finding {
	if hasWiki {
		return Finding{
			Severity: SeverityWarn,
			Check:    "Wiki",
			Message:  "Wiki is enabled",
		}
	}
	return Finding{
		Severity: SeverityOK,
		Check:    "Wiki",
		Message:  "Wiki is disabled",
	}
}

// WikiNoPagesNote returns an INFO finding noting that the wiki is enabled but has no pages,
// so the wiki tab is hidden in the GitHub UI.
func WikiNoPagesNote() Finding {
	return Finding{
		Severity: SeverityInfo,
		Check:    "Wiki",
		Message:  "Wiki is enabled but has no pages (tab hidden in UI) — consider disabling the wiki feature",
	}
}

// WikiRestrictionNote returns an INFO finding noting that wiki restriction
// cannot be checked via the API and must be verified manually.
func WikiRestrictionNote() Finding {
	return Finding{
		Severity: SeverityInfo,
		Check:    "Wiki Restriction",
		Message:  "Wiki restriction ('Restrict editing to collaborators only') cannot be verified via the GitHub API — check manually in repo Settings → General → Wiki",
	}
}
