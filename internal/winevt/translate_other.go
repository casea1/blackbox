package winevt

import (
	"fmt"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// Reviewed are the Security-log event IDs Blackbox translates into report
// rows (some only in certain cases: a person, a removable disk, a
// security registry key). The Audit health page uses it to point out
// audit subcategories whose events nobody reviews (A1).
var Reviewed = map[int]bool{
	1100: true, 1102: true, 1104: true, 1105: true, 1108: true,
	4608: true, 4611: true, 4612: true, 4614: true, 4616: true, 4622: true,
	4624: true, 4625: true, 4634: true, 4647: true, 4648: true, 4656: true, 4657: true, 4663: true, 4670: true,
	4672: true, 4688: true, 4697: true, 4698: true, 4699: true, 4700: true, 4701: true, 4702: true,
	4704: true, 4705: true, 4706: true, 4707: true, 4713: true, 4716: true, 4717: true, 4718: true, 4719: true,
	4720: true, 4722: true, 4723: true, 4724: true, 4725: true, 4726: true, 4727: true, 4728: true, 4729: true,
	4730: true, 4731: true, 4732: true, 4733: true, 4734: true, 4738: true, 4739: true, 4740: true, 4754: true,
	4756: true, 4757: true, 4758: true, 4765: true, 4766: true, 4767: true, 4771: true, 4776: true, 4778: true,
	4779: true, 4781: true, 4800: true, 4801: true, 4826: true, 4907: true,
	4946: true, 4947: true, 4948: true, 4949: true, 4950: true, 5024: true, 5025: true, 5030: true,
	5038: true, 5140: true, 5145: true, 6281: true, 6416: true,
}

// Counted are Security-log events too frequent to list one by one
// (thousands an hour on a busy computer). The report counts them by ID,
// with the original logs in the archive for anyone who needs the detail.
var Counted = map[int]bool{
	4627: true, 4658: true, 4660: true, 4661: true, 4662: true, 4664: true, 4673: true, 4674: true,
	4689: true, 4690: true, 4691: true, 4703: true, 4768: true, 4769: true, 4770: true, 4798: true, 4799: true,
	4944: true, 4945: true, 4957: true, 4985: true, 5058: true, 5059: true, 5061: true,
	5152: true, 5153: true, 5154: true, 5155: true, 5156: true, 5157: true, 5158: true, 5159: true,
	5379: true, 5381: true, 5382: true, 5444: true, 5447: true, 5632: true, 5633: true,
}

// otherSecurity is a Security-log event Blackbox has no translation for:
// a plain row, so nothing the audit policy records is silently dropped
// ("Other security events"). Frequent ones are only counted.
func (t *Translator) otherSecurity(r *Raw) *event.Event {
	if Reviewed[r.EventID] || Counted[r.EventID] {
		return nil
	}
	who := t.subject(r)
	name := EventNames[r.EventID]
	if name == "" {
		name = "no description"
	}
	e := &event.Event{Category: event.CatOther, Severity: event.SevInfo, Action: "other_security", User: who,
		DedupeKey: fmt.Sprintf("other|%d|%s", r.EventID, strings.ToLower(who)),
		Summary:   fmt.Sprintf("Security event %d (%s)", r.EventID, name)}
	if who != "" {
		e.Summary += " by " + who
	}
	if r.AuditFailure() {
		e.Outcome = "failure"
		e.Summary += " — failed"
	}
	e.Summary += "."
	return e
}

// SubcategoryEvents are the Security-log events each advanced audit policy
// subcategory records (the ones the Windows STIGs require).
var SubcategoryEvents = map[string][]int{
	"Credential Validation":              {4774, 4775, 4776, 4777},
	"Security Group Management":          {4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4799},
	"User Account Management":            {4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 4798, 5376, 5377},
	"Other Account Management Events":    {4782, 4793},
	"Plug and Play Events":               {6416, 6419, 6420, 6421, 6422, 6423, 6424},
	"Process Creation":                   {4688, 4696},
	"Account Lockout":                    {4625},
	"Group Membership":                   {4627},
	"Logoff":                             {4634, 4647},
	"Logon":                              {4624, 4625, 4648, 4675},
	"Special Logon":                      {4964, 4672},
	"Other Logon/Logoff Events":          {4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633},
	"File Share":                         {5140, 5142, 5143, 5144, 5168},
	"Detailed File Share":                {5145},
	"Other Object Access Events":         {4671, 4691, 4698, 4699, 4700, 4701, 4702, 5148, 5149, 5888, 5889, 5890},
	"Removable Storage":                  {4656, 4658, 4663},
	"File System":                        {4656, 4658, 4660, 4663, 4664, 4670, 4985, 5051},
	"Handle Manipulation":                {4658, 4690},
	"Registry":                           {4656, 4657, 4658, 4660, 4663, 4670, 5039},
	"Audit Policy Change":                {4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912},
	"Authentication Policy Change":       {4670, 4706, 4707, 4716, 4713, 4717, 4718, 4739, 4864, 4865, 4866, 4867},
	"Authorization Policy Change":        {4703, 4704, 4705, 4670, 4911, 4913},
	"MPSSVC Rule-Level Policy Change":    {4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4956, 4957, 4958},
	"Other Policy Change Events":         {4714, 4819, 4826, 4909, 4910, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5447, 6144, 6145},
	"Sensitive Privilege Use":            {4673, 4674, 4985},
	"IPsec Driver":                       {4960, 4961, 4962, 4963, 4965, 5478, 5479, 5480, 5483, 5484, 5485},
	"Other System Events":                {5024, 5025, 5027, 5028, 5029, 5030, 5032, 5033, 5034, 5035, 5037, 5058, 5059, 6400, 6401, 6402, 6403, 6404, 6405, 6406, 6407, 6408, 6409},
	"Security State Change":              {4608, 4616, 4621},
	"Security System Extension":          {4610, 4611, 4614, 4622, 4697},
	"System Integrity":                   {4612, 4615, 4618, 4816, 5038, 5056, 5057, 5060, 5061, 5062, 6281, 6410},
	"Kerberos Authentication Service":    {4768, 4771, 4772},
	"Kerberos Service Ticket Operations": {4769, 4770, 4773},
}

// SubcategoryReviewed says how the report covers an audit subcategory's
// events: "reviewed" when Blackbox translates some of them into rows,
// "other" when they are listed only as plain "Other security events",
// "counted" when they are only counted, "" when the subcategory is
// unknown.
func SubcategoryReviewed(name string) string {
	ids, ok := SubcategoryEvents[name]
	if !ok {
		return ""
	}
	how := "counted"
	for _, id := range ids {
		switch {
		case Reviewed[id]:
			return "reviewed"
		case !Counted[id]:
			how = "other"
		}
	}
	return how
}

// logonRights names the logon rights 4717/4718 grant or remove.
var logonRights = map[string]string{
	"SeInteractiveLogonRight":           "log on at the keyboard",
	"SeNetworkLogonRight":               "access this computer from the network",
	"SeBatchLogonRight":                 "log on as a batch job",
	"SeServiceLogonRight":               "log on as a service",
	"SeRemoteInteractiveLogonRight":     "log on through Remote Desktop",
	"SeDenyInteractiveLogonRight":       "be refused logon at the keyboard",
	"SeDenyNetworkLogonRight":           "be refused access from the network",
	"SeDenyBatchLogonRight":             "be refused logon as a batch job",
	"SeDenyServiceLogonRight":           "be refused logon as a service",
	"SeDenyRemoteInteractiveLogonRight": "be refused logon through Remote Desktop",
}

// systemAccess is 4717/4718: a logon right granted to or removed from an
// account (T4). Windows grants these itself on every logon of a virtual
// account (an OpenSSH session, a service): left out. A person changing
// them is Medium.
func (t *Translator) systemAccess(r *Raw) *event.Event {
	if t.ignoredAccount(r, "Subject") {
		return nil
	}
	who := t.subject(r)
	target := t.resolve(r.Get("TargetSid"))
	right := firstNonBlank(r.Get("AccessGranted"), r.Get("AccessRemoved"))
	var names []string
	for _, f := range strings.Fields(right) {
		if n, ok := logonRights[f]; ok {
			names = append(names, n)
		} else {
			names = append(names, f)
		}
	}
	what := strings.Join(names, ", ")
	e := &event.Event{Category: event.CatAccount, Severity: event.SevMedium, User: who, Target: target}
	if r.EventID == 4717 {
		e.Action = "logon_right_granted"
		e.Summary = fmt.Sprintf("%s gave %s the right to %s.", orUnknown(who), orUnknown(target), orUnknown(what))
	} else {
		e.Action = "logon_right_removed"
		e.Summary = fmt.Sprintf("%s removed %s's right to %s.", orUnknown(who), orUnknown(target), orUnknown(what))
	}
	e.AddDetail("Right", right)
	e.AddDetail("Account SID", r.Get("TargetSid"))
	return e
}
