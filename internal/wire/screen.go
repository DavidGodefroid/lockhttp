package wire

import (
	"fmt"
	"strings"
	"time"
)

// Bound bounds what the gate sends: the console refuses a request without
// a host or a method and cuts the longer texts.
func Bound(p *ApproveParams) error {
	if p.Host == "" || p.Method == "" {
		return fmt.Errorf("host and method are required")
	}
	for _, s := range []*string{&p.RequestID, &p.Container, &p.Project, &p.Via, &p.Agent, &p.Attribution, &p.Role,
		&p.Parent, &p.TaskID, &p.Branch, &p.SessionID, &p.Phase, &p.TLS, &p.Method, &p.Host, &p.Path,
		&p.QueryHash, &p.BodyFP, &p.ContentType, &p.Rule, &p.Class, &p.ReplayOf} {
		if len(*s) > MaxText {
			*s = (*s)[:MaxText] + "…"
		}
	}
	if len(p.Preview) > MaxPreview {
		p.Preview = p.Preview[:MaxPreview] + "…"
	}
	if len(p.Warnings) > MaxWarnings {
		p.Warnings = p.Warnings[:MaxWarnings]
	}
	if len(p.Refs) > MaxRefs {
		p.Refs = p.Refs[:MaxRefs]
	}
	return nil
}

// ScreenHeader names a held request on its approval screen.
func ScreenHeader(p ApproveParams) string {
	target := p.Host
	if p.Port != 0 && p.Port != 443 && p.Port != 80 {
		target = fmt.Sprintf("%s:%d", p.Host, p.Port)
	}
	if p.Phase == "connect" {
		return "OPEN " + target + " · " + p.Container
	}
	return p.Method + " " + target + " · " + p.Container
}

// ScreenRequester says who sent a held request.
func ScreenRequester(p ApproveParams) string {
	s := "container " + p.Container
	if p.Project != "" {
		s += " (project " + p.Project + ")"
	}
	if p.Agent != "" {
		s += " · agent " + p.Agent + " (declared, " + p.Attribution + ")"
	}
	if p.Via != "" && p.Via != "direct" {
		s += " · via " + p.Via
	}
	return s
}

// ScreenBody are the lines of a held request's approval screen, the same
// on the console and, masked, in a hub ticket.
func ScreenBody(p ApproveParams) []string {
	var out []string
	if p.Phase == "connect" {
		out = append(out, fmt.Sprintf("CONNECT %s:%d", p.Host, p.Port))
		if p.Grant > 0 {
			out = append(out, fmt.Sprintf("y opens %s:%d for %s for %s: reads AND writes, content invisible", p.Host, p.Port, p.Container, time.Duration(p.Grant)*time.Second))
		}
	} else {
		line := p.Method + " " + p.TLS + "://" + p.Host + p.Path
		if p.QueryLen > 0 {
			line += fmt.Sprintf("?…(%d bytes)", p.QueryLen)
		}
		out = append(out, line)
		if p.ReqBytes > 0 || p.ContentType != "" {
			out = append(out, fmt.Sprintf("body %d bytes %s %s", p.ReqBytes, p.ContentType, short(p.BodyFP)))
		}
		if len(p.ReqHeaders) > 0 {
			out = append(out, "headers: "+strings.Join(p.ReqHeaders, " "))
		}
	}
	if p.TaskID != "" || p.Branch != "" || p.Role != "" {
		out = append(out, strings.TrimSpace(fmt.Sprintf("task %s · role %s · parent %s · branch %s", p.TaskID, p.Role, p.Parent, p.Branch)))
	}
	if p.Rule != "" {
		out = append(out, "decided by: "+p.Rule)
	}
	for _, r := range p.Refs {
		out = append(out, "push "+r)
	}
	if p.Preview != "" {
		out = append(out, "", "preview (masked):")
		for _, l := range strings.Split(p.Preview, "\n") {
			out = append(out, "  "+l)
		}
	}
	if p.Pending > 1 {
		out = append(out, "", fmt.Sprintf("%d distinct requests pending under %s %s%s: y approves this one only", p.Pending, p.Method, p.Host, p.Path))
	}
	if p.ReplayOf != "" {
		out = append(out, "replay of "+p.ReplayOf+" with another body: not covered by its approval")
	}
	if p.ClientGone {
		out = append(out, "", "client gone: y lets the same request through once in the next 10 minutes")
	}
	out = append(out, "request "+p.RequestID)
	return out
}

func short(fp string) string {
	if len(fp) > 19 {
		return fp[:19] + "…"
	}
	return fp
}
