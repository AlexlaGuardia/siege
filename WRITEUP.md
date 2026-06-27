# I broke my own governed MCP server by hand, then built the scanner that catches the class

A few weeks back I shipped Warden, a governance layer that sits in front of an MCP server and enforces who can read what. Role-based, field-level. The demo had a `support` role that could list customer accounts but never see their billing `tier`. The `tier` field is stripped from everything support gets back.

I was poking at it the way you poke at your own work when you don't quite trust it.. I tried this:

```
query_resource("accounts", {"tier": "Enterprise"})
```

Six rows came back. Acme Corp, Initech, Umbrella, Hooli, Stark, Wayne. The support role can't *see* the tier, but the query layer still accepted it as a filter. So you ask for every Enterprise account, and the ones that match tell you their tier by simply existing in the result. Redaction held on the output. It leaked through the input.

That's the bug. It's small and it's boring and it's exactly the kind of thing that ships.

Here's the part that bothered me more than the bug. I went and ran the MCP security scanners on it. The ones everyone uses now read the tool *manifest*: they look at the tool descriptions, grep for poisoned instructions, flag suspicious-looking metadata. Good tools. They all came back green. They have to. There is nothing wrong with the manifest. The `query_resource` tool description is honest. The bug only exists when the server runs and a real role makes a real call. A scanner that reads text can't reach it.

So I built the thing that can. It's called Siege.

## Run the server, don't read it

Siege points at a live MCP server and behaves like an attacker against it, as real roles. No manifest grep. It connects as each identity you give it, and it diffs what comes back.

The wedge is runtime authorization. Static scanners own static tool-poisoning and they're fine at it; I'm not going to out-grep them. What nobody ships is a tool that exercises the running server as different users and tries to break access control. The RBAC vendors all say "you should red-team your authorization scope" as advice. Siege is that advice turned into a thing you run.

The hard rule I gave myself: no hardcoded field names, no hardcoded roles. If it only caught the Warden bug because I told it about `tier`, it would be a unit test, not a scanner. So the method is differential. Learn the schema and the real values from the most-permissive identity, the one that sees everything. Then for every restricted role, diff what it sees against that, and probe the gaps.

Four detectors came out of that, all role-relative:

- **Redacted-field filter leak.** The Warden bug, generalized. For any field stripped from a role's output, try it as a filter. If filtering on it returns fewer rows than the baseline, the hidden value just leaked through the difference.
- **Row-scope escalation.** A role whose normal view is scoped to a subset (region = West, say) tries an out-of-scope filter value. If `region=East` returns rows it shouldn't have, the filter ran against the full dataset instead of the scoped one.
- **ID enumeration.** The list path is governed, the single-record lookup often isn't. So `get_record` on guessed ids walks straight past the scoping that `query_resource` enforces. Classic IDOR, MCP edition.
- **Forbidden-resource read.** A role can't even list a resource, but `get_record` hands one over anyway. Access checked on list and query, forgotten on the by-id path.

The last three I never found by hand. they fell out of writing the first one generically.. build the engine for one bug and it pulls the next few with it.

## The money shot

I keep two Warden builds: the vulnerable commit and the fixed one. Siege runs against both.

```
BEFORE — vulnerable Warden (4938bdf)
## 1. [HIGH] Redacted field 'tier' leaks through filter predicate on 'accounts'
   Found as role: support
   Reproduce: query_resource({"resource_type":"accounts","filters":{"tier":"Enterprise"}})
   baseline_count: 8   filtered_count: 6
   leaked_records: ['Acme Corp', 'Initech', 'Umbrella Co', 'Hooli', 'Stark Industries', 'Wayne Enterprises']

AFTER — fixed Warden (7188eed)
   No findings. The probed classes held.

VERDICT: PASS — Siege caught the bug and cleared the fix.
```

Every finding carries an exact, replayable repro: the tool, the arguments, the rows that came back. You can paste it into your own client and watch it leak. And to make sure the detectors aren't no-ops that pass everything, there's an intentionally-broken fixture server in the repo. Siege fires all four detectors on it, including the critical forbidden-resource read. it's in there if you want to watch it go.

## The second class: did the agent actually get owned

Tool-poisoning is the attack everyone talks about: hide an instruction in a tool description or a tool's output, and the agent reading it does what the attacker said instead of what the user asked. Static scanners ask "does this description look hostile." Siege asks a different question. Does the agent get hijacked.

So it runs a real agent loop. Benign read tool, plus an `export_record` sink that ships data to a URL. The user's task is read-only: summarize record 1, that's all. Then Siege injects each payload through the description channel and the output channel and watches whether the model fires the sink at an attacker destination it was never asked to touch. A hijack is observed, not inferred from text.

The output is a matrix, not a verdict. Five payloads across two channels: system-block spoofing (run through both the description and the output), plain policy text, role-confusion, task-decomposition. You see which ones steered the model and which bounced off. A clean 0-of-5 is a real result too, and a regression guard for the day you bump model versions and a framing that used to bounce stops bouncing.

## What it doesn't do

The report names the classes it ran and prints what it skipped. MCP servers only for now, no OpenAI function-calling, that's a later expansion. stdio transport today, HTTP next. The silent-failure class (does the server claim success while returning empty data) is designed and not yet shipped. No "finds all vulnerabilities" anywhere in the output, because that sentence is how scanners lie.

And it only attacks my own fixtures and servers I explicitly opt in. Pointing a runtime red-team tool at someone else's live server without an invite isn't a demo.

## Where it sits

Siege is the offense leg of a three-piece stack. Warden governs the server. Crumb attributes every call to the person who authorized it. Siege is the part that tries to break what Warden built. Build the wall, then lay siege to it.

Code's public: [github.com/AlexlaGuardia/siege](https://github.com/AlexlaGuardia/siege). It's v0.1 and it's narrow on purpose. Runs against a live server, as real roles. The part the manifest can't show you.
