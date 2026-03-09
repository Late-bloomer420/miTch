# miTch — Why Users Care When They See It

> Not implementation-ready. Thinking space only.
> This document captures the evidence and argument for why visibility works.

---

## The Privacy Paradox — and Why It's a Design Problem

The common objection: "People say they care about privacy but don't change behaviour."
This is called the privacy paradox. It's real — but it's mostly a design problem, not human nature.

People don't read privacy policies because privacy policies are intentionally unreadable.
People click through cookie banners because cookie banners are designed by lawyers to be ignored.
That is not evidence people don't care. It is evidence that dark patterns work.

The moment you make privacy information concrete, specific, and visible at the right moment —
people respond. The evidence is consistent and strong.

---

## The Evidence

### iOS App Tracking Transparency (ATT) — Apple, 2021

Apple introduced a single popup at the moment an app tried to track a user across other apps
and websites. Plain language. One tap to say no.

**Result: 85% of users chose "Ask App Not to Track."**

Not privacy enthusiasts. Not tech-savvy users. Normal people.
The interest was always there. Nobody had shown them the question in a way they could answer.

This is the single most important proof point for what miTch is building.
The daily review is the ATT popup — but for every data interaction, every day, over time.

### Facebook Data Downloads — GDPR, 2018

When GDPR forced Facebook to let users download their own data, the downloads went viral.
People were genuinely shocked at what was in there — the granularity, the history,
the categories of data collected that users had no idea existed.

The data existed before. The difference was visibility.

### Cambridge Analytica — 2018

The abstract concept of "data collection" meant nothing to most people for years.
Then it became concrete: *your* Facebook data, used to target *you* in a political campaign.
Then everyone cared. Regulators moved. Laws changed.

Nothing about the underlying data practice was new. The visibility changed everything.

### Apple Privacy Nutrition Labels — App Store, 2020

Apple introduced standardised privacy labels on every App Store listing showing exactly
what data an app collects and how it's used. Downloads of privacy-invasive apps dropped.
Downloads of privacy-respecting alternatives increased.

Informed choice, made visible, changes behaviour.

---

## The Design Principle That Follows

**Visibility works. Dark patterns work in the opposite direction.**

The gap is not that users don't care. The gap is that the information has always been:
- Buried in documents nobody reads
- Shown at the wrong moment (after consent is already given)
- Written in language designed to obscure, not inform
- Framed as all-or-nothing (accept everything or don't use the service)

miTch's daily review is the opposite of all four:
- Surfaced automatically, no reading required
- Shown after the transaction (no pressure, no decision, just information)
- Written in plain language ("Your age was shared. Your name was not.")
- Granular (exactly which fields, not a vague category)

---

## When to Show It — The Critical Timing Insight

The iOS ATT worked because it appeared **at the exact moment the thing was happening.**
Not in settings. Not in a dashboard. At the door.

miTch applies this principle with a split:

**At transaction time:** minimal — what leaves, what doesn't, one tap.
The decision the user is actually making right now. No extra cognitive load.

**After the day:** the review — everything that happened, timestamped, with danger levels.
No pressure. No decision needed. Just information the user can build intuition from.

**Only when something is wrong:** proactive notification.
If every transaction triggers a notification, notifications mean nothing.
The signal only works if it's rare and specific.

---

## What This Means for Product Design

1. **Silence is the primary signal.** Green ambient indicator = everything was clean.
   The user learns this quickly and trusts it. When it changes, they notice.

2. **The daily review trains intuition over time.**
   After a week, the user knows what a clean transaction looks like.
   After a month, they notice when something is different.
   After a year, they have a picture of their data life that no institution can show them.

3. **Plain language is not dumbing down — it is the product.**
   "VP token validated" is not the product. "Your age was confirmed. Nothing else was shared."
   is the product. The translation IS the value.

4. **The escalation path completes the loop.**
   Seeing a risk is useless without knowing what to do about it.
   miTch doesn't just show the danger — it connects the user to the DPA, the lawyer,
   the specialist who can actually help. That is what makes it actionable, not just informative.

---

## The Deeper Argument

Every institution that processes data about you has a complete picture of what they know.
The compliance officer at your bank can query your entire profile. The hospital has your history.
The pharmacy tracks your prescriptions. The advertiser has your behaviour model.

You have none of that. You have no view into what's being built about you, by whom, over what time.

miTch is not about restricting what institutions can do.
It is about giving you the same visibility they have.
Not as a technical curiosity. As a normal part of your daily digital life —
the same way you check your bank balance without thinking about the underlying database.

That picture, once someone sees it, doesn't leave their mind.
That is the product.
